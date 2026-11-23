module Main (main) where

import Api (api, servidor)
import Banco (iniciarBanco)
import Control.Monad (unless)
import Network.Wai.Handler.Warp (run)
import Servant (Context (..), serveWithContext)
import Servant.Auth.Server (defaultCookieSettings, defaultJWTSettings, readKey, writeKey)
import System.Directory (doesFileExist)

main :: IO ()
main = do
  banco <- iniciarBanco

  -- A chave que assina os JWTs fica em chave.jwk (não suba esse arquivo para o GitHub).
  -- Se ela for apagada, todos os logins existentes deixam de valer.
  let arquivoChave = "chave.jwk"
  existe <- doesFileExist arquivoChave
  unless existe (writeKey arquivoChave)
  chave <- readKey arquivoChave

  let jwt = defaultJWTSettings chave
      contexto = defaultCookieSettings :. jwt :. EmptyContext

  putStrLn "StudyHub em http://localhost:8080"
  run 8080 (serveWithContext api contexto (servidor banco jwt))