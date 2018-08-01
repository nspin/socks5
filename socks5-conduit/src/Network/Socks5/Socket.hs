module Network.Socks5.Socket
    ( socksEndpointFromSockAddr
    ) where

import Network.Socket
import Network.Socks5.Types

socksEndpointFromSockAddr :: SockAddr -> Maybe SocksEndpoint
socksEndpointFromSockAddr (SockAddrInet port host) = Just $ SocksEndpoint (SocksHostIPv4 host) (fromIntegral port)
socksEndpointFromSockAddr (SockAddrInet6 port _ (a, b, c, d) _) = Just $ SocksEndpoint (SocksHostIPv6 a b c d) (fromIntegral port)
socksEndpointFromSockAddr _ = Nothing
