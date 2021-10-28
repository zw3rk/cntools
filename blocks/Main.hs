{-# language OverloadedStrings, LambdaCase, TypeApplications, BangPatterns #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Main where

import Network.Wreq
import Data.ByteString.Lazy as BSL (ByteString, length)
import qualified Data.ByteString as BS
import System.Environment (lookupEnv)

import Data.Map as Map
import Data.Aeson (Value, decodeFileStrict)
import Data.Aeson.Lens (_String, _Number, _Integer, _Double, key)
import Data.Text (Text)
import qualified Data.Text as T
import Control.Monad (filterM)

import Data.Char (digitToInt)

import qualified Crypto.Hash.BLAKE2.BLAKE2b as B2b

-- Low level stuff.
import Data.Binary (encode, decode)
import Data.Bits (xor, unsafeShiftL)
import Data.Word (Word64)
import Data.Ratio

-- Lensy stuff
import Control.Lens
import Data.ByteString.Lens (packedChars, packedBytes, unpackedBytes)
import Data.ByteString.Base16.Lens (_Hex)
import Data.Text.Lens (unpacked)
import Control.Lens.Iso (lazy)


import GHC.Stack (HasCallStack)

-- Time/Date stuff
import Data.Time.Clock.POSIX
import Data.Time.LocalTime
import Data.Time.Format.ISO8601
import Data.Time.Zones
import Data.Time.Zones.All

-- FFI stuff
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils
import Foreign.Ptr

data SeedValue
data SignKeyValue
data VerKeyValue
data ProofValue
data OutputValue

type SeedPtr = Ptr SeedValue
type SignKeyPtr = Ptr SignKeyValue
type VerKeyPtr = Ptr VerKeyValue
type ProofPtr = Ptr ProofValue
type OutputPtr = Ptr OutputValue

newtype Seed = Seed { unSeed :: ForeignPtr SeedValue }
newtype SignKey = SignKey { unSignKey :: ForeignPtr SignKeyValue }
newtype Proof = Proof { unProof :: ForeignPtr ProofValue }
newtype Output = Output { unOutput :: ForeignPtr OutputValue }

type Resp = Response (Map String Value)

blockfrostGet :: HasCallStack => BS.ByteString -> String -> IO (Response ByteString)
blockfrostGet apiKey path = getWith opts $ "https://cardano-mainnet.blockfrost.io/api/v0/" <> path
  where opts = defaults & header "project_id" .~ [ apiKey ]

readDecimal :: Text -> Integer
readDecimal = T.foldl' step 0
  where step a c = a * 10 + toInteger (digitToInt c)


mkSeed :: HasCallStack => Integer -> Text -> BS.ByteString
mkSeed slot eta0 = (zipWith xor (seedbytes ^. unpackedBytes) (slotbytes ^. unpackedBytes)) ^. packedBytes
  where seedbytes = B2b.hash 32 mempty (BS.pack [0,0,0,0,0,0,0,1])
        slotbytes :: BS.ByteString
        slotbytes = B2b.hash 32 mempty ((encode (fromInteger slot :: Word64) ^. from lazy <> (eta0 ^. unpacked . packedChars . _Hex)))


-- This could be easy if we just picked it from consensus. However that brings in
-- a massive dependency tree...
-- So let's go directly via C FFI (taken from the Cardano.Crypto.VRF.Praos module)
-- Raw low-level FFI bindings.
--

foreign import ccall "crypto_vrf_proofbytes" crypto_vrf_proofbytes :: CSize
foreign import ccall "crypto_vrf_publickeybytes" crypto_vrf_publickeybytes :: CSize
foreign import ccall "crypto_vrf_secretkeybytes" crypto_vrf_secretkeybytes :: CSize
foreign import ccall "crypto_vrf_seedbytes" crypto_vrf_seedbytes :: CSize
foreign import ccall "crypto_vrf_outputbytes" crypto_vrf_outputbytes :: CSize

foreign import ccall "crypto_vrf_keypair_from_seed" crypto_vrf_keypair_from_seed :: VerKeyPtr -> SignKeyPtr -> SeedPtr -> IO CInt
foreign import ccall "crypto_vrf_sk_to_pk" crypto_vrf_sk_to_pk :: VerKeyPtr -> SignKeyPtr -> IO CInt
foreign import ccall "crypto_vrf_sk_to_seed" crypto_vrf_sk_to_seed :: SeedPtr -> SignKeyPtr -> IO CInt
foreign import ccall "crypto_vrf_prove" crypto_vrf_prove :: ProofPtr -> SignKeyPtr -> Ptr CChar -> CULLong -> IO CInt
foreign import ccall "crypto_vrf_verify" crypto_vrf_verify :: OutputPtr -> VerKeyPtr -> ProofPtr -> Ptr CChar -> CULLong -> IO CInt

foreign import ccall "crypto_vrf_proof_to_hash" crypto_vrf_proof_to_hash :: OutputPtr -> ProofPtr -> IO CInt

foreign import ccall "randombytes_buf" randombytes_buf :: Ptr a -> CSize -> IO ()


-- Wrapper for the C calls
certSizeVRF :: Int
certSizeVRF = fromIntegral $! crypto_vrf_proofbytes

signKeySizeVRF :: Int
signKeySizeVRF = fromIntegral $! crypto_vrf_secretkeybytes

verKeySizeVRF :: Int
verKeySizeVRF = fromIntegral $! crypto_vrf_publickeybytes

vrfKeySizeVRF :: Int
vrfKeySizeVRF = fromIntegral $! crypto_vrf_outputbytes


copyFromByteString :: HasCallStack => Ptr a -> BS.ByteString -> Int -> IO ()
copyFromByteString ptr bs lenExpected =
  BS.useAsCStringLen bs $ \(cstr, lenActual) ->
    if (lenActual >= lenExpected) then
      copyBytes (castPtr ptr) cstr lenExpected
    else
      error $ "Invalid input size, expected at least " <> show lenExpected <> ", but got " <> show lenActual

mkProof :: HasCallStack => IO Proof
mkProof = fmap Proof $ newForeignPtr finalizerFree =<< mallocBytes (certSizeVRF)

mkSignKey :: HasCallStack => IO SignKey
mkSignKey = fmap SignKey $ newForeignPtr finalizerFree =<< mallocBytes signKeySizeVRF

skFromBytes :: HasCallStack => BS.ByteString -> IO SignKey
skFromBytes bs
  | bsLen /= signKeySizeVRF
  = error ("Invalid sk length " <> show @Int bsLen <> ", expecting " <> show @Int signKeySizeVRF)
  | otherwise
  = do
      sk <- mkSignKey
      withForeignPtr (unSignKey sk) $ \ptr ->
        copyFromByteString ptr bs signKeySizeVRF
      return sk
  where
    bsLen = BS.length bs

mkOutput :: HasCallStack => IO Output
mkOutput = fmap Output $ newForeignPtr finalizerFree =<< mallocBytes (fromIntegral crypto_vrf_outputbytes)

outputBytes :: HasCallStack => Output -> IO BS.ByteString
outputBytes (Output op) = withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, fromIntegral crypto_vrf_outputbytes)

prove :: HasCallStack => SignKey -> BS.ByteString -> IO (Maybe Proof)
prove sk msg =
    withForeignPtr (unSignKey sk) $ \skPtr -> do
      proof <- mkProof
      BS.useAsCStringLen msg $ \(m, mlen) -> do
        withForeignPtr (unProof proof) $ \proofPtr -> do
          crypto_vrf_prove proofPtr skPtr m (fromIntegral mlen) >>= \case
            0 -> return $ Just $! proof
            _ -> return Nothing

outputFromProof :: HasCallStack => Proof -> IO (Maybe Output)
outputFromProof (Proof p) =
    withForeignPtr p $ \ptr -> do
      output <- mkOutput
      withForeignPtr (unOutput output) $ \outputPtr -> do
        crypto_vrf_proof_to_hash outputPtr ptr >>= \case
          0 -> return $ Just $! output
          _ -> return Nothing


vrfEvalCertificate :: HasCallStack => BS.ByteString -> BS.ByteString -> IO BS.ByteString
vrfEvalCertificate seed skey = do
   sk <- skFromBytes $ skey
   Just proof <- prove sk seed
   Just hash  <- outputFromProof proof
   outputBytes hash

uintegerFromBytes :: BS.ByteString -> Integer
uintegerFromBytes bs =
    case BS.uncons bs of
      Nothing        -> 0
      Just (w0, ws0) -> go (fromIntegral w0) ws0
  where
    go !acc ws =
      case BS.uncons ws of
        Nothing       -> acc
        Just (w, ws') -> go (acc `unsafeShiftL` 8 + fromIntegral w) ws'


isSlotLeader :: HasCallStack => Integer -> Double -> Double -> Text -> BS.ByteString -> IO Bool
isSlotLeader slot activeSlotCoeff sigma eta0 skeyHex = do
   cert <- vrfEvalCertificate (mkSeed slot eta0) (skeyHex ^. _Hex)
   let certNat = uintegerFromBytes $ cert
       certNatMax = 2 ^ 512
       denominator = certNatMax - certNat
       q = certNatMax % denominator
       c = log (1.0 - activeSlotCoeff)
       sigmaOfF = exp (-sigma * c)
   return $ fromRational q <= sigmaOfF

-- I don't understand why this needs to be so hard in haskell :-/
-- need to use @tz@ and @time@ just to be able to construct a ZonedTime
-- from a tz description and a timestamp. Now we can use @iso8601Show@ on it
-- to generate a properly zoned ios8601 timestamp.
posixToZonedTime :: BS.ByteString -> POSIXTime -> ZonedTime
posixToZonedTime name sec = utcToZonedTime (timeZoneForUTCTime tz utcTime) $ utcTime
  where
    Just tz = tzByName name
    utcTime = posixSecondsToUTCTime sec

main :: HasCallStack => IO ()
main = do

  Just apiKey  <- fmap (^. packedChars) <$> lookupEnv "BLOCKFROST_API_KEY"
  Just tz      <- fmap (^. packedChars) <$> lookupEnv "TZ"
  Just poolId  <- lookupEnv "POOL_ID"
  Just vrfFile <- lookupEnv "VRF_FILE"
  
  params <- blockfrostGet apiKey "epochs/latest/parameters"
  let Just epoch = params ^? responseBody . key "epoch" . _Integer
  let Just eta0 = params ^? responseBody . key "nonce" . _String
  
  params <- blockfrostGet apiKey $ "pools/" <> poolId
  let Just sigma = params ^? responseBody . key "active_size" . _Double
  let Just poolStake = readDecimal <$> params ^? responseBody . key "active_stake" . _String

  params <- blockfrostGet apiKey $ "epochs/latest"
  let Just totalStake = readDecimal <$> params ^? responseBody . key "active_stake" . _String

  params <- blockfrostGet apiKey $ "genesis"
  let Just epochLength = params ^? responseBody . key "epoch_length" . _Integer
  let Just activeSlotCoeff = params ^? responseBody . key "active_slots_coefficient" . _Double
  let Just slotLength = params ^? responseBody . key "slot_length" . _Integer

  -- Epoch 211 First Slot
  params <- blockfrostGet apiKey $ "blocks/4555184"
  let Just firstSlot = params ^? responseBody . key "slot" . _Integer

  let firstSlotOfEpoch = firstSlot + (epoch - 211) * epochLength

  Just vrf <- decodeFileStrict @Value vrfFile
  let vrfBytes = (T.drop 4 $ vrf ^. key "cborHex" . _String) ^. unpacked . packedChars

  print epoch
  print eta0
  print sigma
  print poolStake
  print totalStake

  print epochLength
  print activeSlotCoeff
  print slotLength

  print firstSlot

  print $ crypto_vrf_proofbytes
    
  print $ firstSlotOfEpoch
  print vrfBytes

  slots <- filterM (\slot -> isSlotLeader slot activeSlotCoeff sigma eta0 vrfBytes) [firstSlotOfEpoch..(firstSlotOfEpoch+epochLength)]

  flip mapM slots $ \slot -> do
    putStrLn $ "Leader At Slot: " <> (show $ fromInteger slot - firstSlotOfEpoch) <> " - Local Time " <> iso8601Show (posixToZonedTime tz $ fromInteger slot + slotPOSIXOffset)
     
  return ()

  where
    slotPOSIXOffset = 1591566291

