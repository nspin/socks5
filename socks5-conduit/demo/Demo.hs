{-# LANGUAGE OverloadedStrings #-}

import Network.Socks5
import Network.Socks5.Conduit (socksClient, socksServer)

import Control.Monad.Trans.Class (lift)
import Data.ByteString (ByteString)
import Data.Conduit.Combinators (stdout)
import Data.Conduit.Network (clientSettings, serverSettings)

-- main :: IO ()
-- main = socksServer pref (serverSettings 8080 "localhost")
--   where
--     pref = SocksAuthenticationPreferenceUsernamePassword $ \creds -> Right creds <$ print creds

main :: IO ()
main = socksClient SocksClientAuthenticationPreferenceNone set endpoint $ \_ send -> do
    let sendLine line = lift $ send line >> send "\r\n"
    sendLine "GET / HTTP/1.1"
    sendLine "Host: ipecho.nickspinale.com"
    sendLine "Connection: close"
    sendLine ""
    stdout
  where
    set = clientSettings 9050 "localhost"
    endpoint = SocksEndpoint (SocksHostName "ipecho.nickspinale.com") 80
