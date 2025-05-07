module JWT.Parser 
  ( parseJWT
  , decodeJWT
  , JWTParts(..)
  , JWTHeader(..)
  , JWTPayload(..)
  , JWTClaim(..)
  , ValidationError(..)
  ) where

import Data.List.Split (splitOn)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Aeson as A
import qualified Data.Map.Strict as Map
import qualified Data.Text.Lazy.Encoding as TLE
import qualified Data.Text.Lazy as TL
import qualified Data.ByteString.Base64 as B64
import Data.Maybe (fromMaybe)


import Data.List.Split (splitOn)

-- | Represents the three parts of a JWT token
data JWTParts = JWTParts 
  { jwtHeader :: String
  , jwtPayload :: String
  , jwtSignature :: String
  } deriving (Show, Eq)

  -- | JWT Header structure
data JWTHeader = JWTHeader
  { jwsAlg :: Maybe String  -- ^ Algorithm used
  , jwsTyp :: Maybe String  -- ^ Token type
  , jwsKid :: Maybe String  -- ^ Key ID
  , jwsOther :: Map.Map String A.Value  -- ^ Other header fields
  } deriving (Show, Eq)

  -- | JWT Claim value
data JWTClaim = 
    StringClaim String
  | NumberClaim Double
  | BoolClaim Bool
  | NullClaim
  | ListClaim [JWTClaim]
  | MapClaim (Map.Map String JWTClaim)
  deriving (Show, Eq)

  -- | JWT Payload structure
data JWTPayload = JWTPayload
  { jwtIss :: Maybe String  -- ^ Issuer
  , jwtSub :: Maybe String  -- ^ Subject
  , jwtAud :: Maybe String  -- ^ Audience
  , jwtExp :: Maybe Integer -- ^ Expiration time
  , jwtNbf :: Maybe Integer -- ^ Not before time
  , jwtIat :: Maybe Integer -- ^ Issued at time
  , jwtJti :: Maybe String  -- ^ JWT ID
  , jwtClaims :: Map.Map String JWTClaim  -- ^ Custom claims
  } deriving (Show, Eq)

  -- | Decoded JWT structure
data DecodedJWT = DecodedJWT
  { decodedHeader :: JWTHeader
  , decodedPayload :: JWTPayload
  , decodedSignature :: String
  } deriving (Show, Eq)

-- | Validation errors
data ValidationError =
    InvalidTokenFormat String
  | InvalidBase64 String
  | InvalidJSON String
  | MissingRequiredClaim String
  deriving (Show, Eq)



-- | Parse a JWT token string into its component parts
parseJWT :: String -> Either ValidationError JWTParts
parseJWT token = 
  case splitOn "." token of
    [h, p, s] -> Right $ JWTParts h p s
    _ -> Left $ InvalidTokenFormat "Token must contain exactly two dots separating three components"


-- | Decode a JWT token into its structured components
decodeJWT :: String -> Either ValidationError DecodedJWT
decodeJWT token = do
  parts <- parseJWT token
  header <- decodeHeader (jwtHeader parts)
  payload <- decodePayload (jwtPayload parts)
  return $ DecodedJWT header payload (jwtSignature parts)


-- | Decode the JWT header
decodeHeader :: String -> Either ValidationError JWTHeader
decodeHeader h = do
  json <- decodeBase64Url h
  case A.decode json of
    Nothing -> Left $ InvalidJSON "Failed to parse header as JSON"
    Just v -> Right $ parseHeaderJson v

-- | Decode the JWT payload
decodePayload :: String -> Either ValidationError JWTPayload
decodePayload p = do
  json <- decodeBase64Url p
  case A.decode json of
    Nothing -> Left $ InvalidJSON "Failed to parse payload as JSON"
    Just v -> Right $ parsePayloadJson v

-- | Decode base64url string to JSON
decodeBase64Url :: String -> Either ValidationError BL.ByteString
decodeBase64Url str = 
  let 
    -- Replace base64url specific chars and add padding
    normalized = fixBase64Padding $ T.unpack $ T.replace (T.pack "-") (T.pack "+") $ T.replace (T.pack "_") (T.pack "/") $ T.pack str
  in
    case B64.decode (BLC.pack normalized) of
      Left err -> Left $ InvalidBase64 $ "Failed to decode base64: " ++ show err
      Right bs -> Right $ BL.fromStrict bs


-- | Fix base64 padding
fixBase64Padding :: String -> String
fixBase64Padding s =
  let len = length s
      remainder = len `mod` 4
  in if remainder == 0 
     then s
     else s ++ replicate (4 - remainder) '='


-- | Parse header JSON into a JWTHeader structure
parseHeaderJson :: A.Value -> JWTHeader
parseHeaderJson (A.Object o) =
  let 
    alg = case A.lookup "alg" o of
            Just v -> A.decode (A.encode v)
            Nothing -> Nothing
    typ = case A.lookup "typ" o of
            Just v -> A.decode (A.encode v)
            Nothing -> Nothing 
    kid = case A.lookup "kid" o of
            Just v -> A.decode (A.encode v)
            Nothing -> Nothing
    -- Filter out the known fields and keep the rest
    otherFields = Map.fromList $ filter (\(k, _) -> k /= "alg" && k /= "typ" && k /= "kid") $ A.toList o
  in
    JWTHeader alg typ kid otherFields
parseHeaderJson _ = JWTHeader Nothing Nothing Nothing Map.empty


-- | Parse claim value
parseClaimValue :: A.Value -> JWTClaim
parseClaimValue (A.String s) = StringClaim (T.unpack s)
parseClaimValue (A.Number n) = NumberClaim (realToFrac n)
parseClaimValue (A.Bool b) = BoolClaim b
parseClaimValue A.Null = NullClaim
parseClaimValue (A.Array arr) = ListClaim (map parseClaimValue arr)
parseClaimValue (A.Object obj) = MapClaim (Map.map parseClaimValue obj)


-- | Parse payload JSON into a JWTPayload structure
parsePayloadJson :: A.Value -> JWTPayload
parsePayloadJson (A.Object o) =
  let 
    -- Go back to the original case expressions which worked
    iss = case Map.lookup "iss" o of
            Just v -> A.decode (A.encode v) 
            Nothing -> Nothing
    sub = case Map.lookup "sub" o of
            Just v -> A.decode (A.encode v)
            Nothing -> Nothing
    aud = case Map.lookup "aud" o of
            Just v -> A.decode (A.encode v)
            Nothing -> Nothing
    exp = case Map.lookup "exp" o of
            Just v -> A.decode (A.encode v)
            Nothing -> Nothing
    nbf = case Map.lookup "nbf" o of
            Just v -> A.decode (A.encode v)
            Nothing -> Nothing
    iat = case Map.lookup "iat" o of
            Just v -> A.decode (A.encode v)
            Nothing -> Nothing
    jti = case Map.lookup "jti" o of
            Just v -> A.decode (A.encode v)
            Nothing -> Nothing
    
    -- Filter out the standard claims and parse the remaining custom claims
    standardClaims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]
    customClaims = Map.fromList 
                 $ map (\(k, v) -> (k, parseClaimValue v)) 
                 $ filter (\(k, _) -> k `notElem` standardClaims) 
                 $ Map.toList o
  in
    JWTPayload iss sub aud exp nbf iat jti customClaims
parsePayloadJson _ = JWTPayload Nothing Nothing Nothing Nothing Nothing Nothing Nothing Map.empty









