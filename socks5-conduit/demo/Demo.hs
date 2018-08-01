{-# LANGUAGE OverloadedStrings #-}

import Data.Conduit.Network (serverSettings)
import Network.Socks5.Conduit (socksServer)

main :: IO ()
main = socksServer (serverSettings 8080 "localhost")