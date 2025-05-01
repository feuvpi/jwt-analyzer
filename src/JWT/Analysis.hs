module JWT.Analysis
  ( analyzeHeader
  , analyzePayload
  ) where

import JWT.Parser (JWTParts(..))

-- | Analyze the header part of a JWT for potential issues
analyzeHeader :: String -> [String]
analyzeHeader _ = ["Header analysis not implemented yet"]

-- | Analyze the payload part of a JWT for potential issues
analyzePayload :: String -> [String]
analyzePayload _ = ["Payload analysis not implemented yet"]
