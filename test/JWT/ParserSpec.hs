module JWT.ParserSpec (spec) where

import Test.Hspec
import JWT.Parser

spec :: Spec
spec = do
  describe "JWT.Parser" $ do
    describe "parseJWT" $ do
      it "parses a valid JWT token" $ do
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        case parseJWT token of
          Left _ -> expectationFailure "Failed to parse valid JWT token"
          Right parts -> do
            jwtHeader parts `shouldBe` "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            jwtPayload parts `shouldBe` "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
            jwtSignature parts `shouldBe` "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
      
      it "returns an error for an invalid JWT token" $ do
        let invalid = "invalid"
        case parseJWT invalid of
          Left (InvalidTokenFormat _) -> return ()
          Left _ -> expectationFailure "Expected InvalidTokenFormat error but got different error"
          Right _ -> expectationFailure "Expected error but parsing succeeded"