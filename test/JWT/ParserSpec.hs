module JWT.ParserSpec where

import Test.Hspec
import JWT.Parser

spec :: Spec
spec = do
  describe "parseJWT" $ do
    it "should parse a valid JWT token" $ do
      let token = "header.payload.signature"
      parseJWT token  Right (JWTParts "header" "payload" "signature")
    
    it "should return an error for invalid tokens" $ do
      let invalid = "header.payload"
      parseJWT invalid  Left "Invalid JWT token format: must contain exactly two dots separating three components"
