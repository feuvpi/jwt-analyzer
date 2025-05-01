module JWT.Parser 
  ( parseJWT
  , JWTParts(..)
  ) where

import Data.List.Split (splitOn)

-- | Represents the three parts of a JWT token
data JWTParts = JWTParts 
  { jwtHeader :: String
  , jwtPayload :: String
  , jwtSignature :: String
  } deriving (Show, Eq)

-- | Parse a JWT token string into its component parts
parseJWT :: String -> Either String JWTParts
parseJWT token = 
  case splitOn "." token of
    [h, p, s] -> Right $ JWTParts h p s
    _ -> Left "Invalid JWT token format: must contain exactly two dots separating three components"
