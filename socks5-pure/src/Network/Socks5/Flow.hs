{-# LANGUAGE RankNTypes #-}

module Network.Socks5.Flow
    (

    -- * Client
      socksClientAuthenticateNone
    , socksClientAuthenticateUsernamePassword
    , socksClientCommand

    -- * Server
    , socksServerAuthenticateNone
    , socksServerGetUsernamePassword
    , socksServerUsernamePasswordSuccess
    , socksServerUsernamePasswordFailure
    , socksServerUsernamePasswordFailure'
    , socksServerSuccess
    , socksServerFailure

    -- * Context
    , SocksContext(..)
    , SocksException(..)

    -- * Internal
    , socksClientJustSelectMethod
    , socksServerJustSelectMethod
    , socksClientJustAuthenticateUsernamePassword

    ) where

import Network.Socks5.Types

import Control.Exception (Exception)
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.Serialize
import Data.Word (Word8)


data SocksException =
      SocksProtocolException String -- ^ deserialization failure
    | SocksNoAcceptibleMethodsException
    | SocksUsernamePasswordAuthenticationFailureException Word8
    | SocksReplyFailureException SocksReplyFailure
    deriving (Show, Eq)

instance Exception SocksException

-- TODO: Improve this interface
data SocksContext m = SocksContext
    { socksContextSend :: ByteString -> m ()
    , socksContextRecv :: forall r. Get r -> m (Either String r)
    , socksContextThrow :: forall a. SocksException -> m a
    }

socksSend :: Serialize a => SocksContext m -> a -> m ()
socksSend ctx a = socksContextSend ctx . runPut $ put a

socksRecv :: (Monad m, Serialize a) => SocksContext m -> m a
socksRecv ctx = (socksContextRecv ctx) get >>= either (socksContextThrow ctx . SocksProtocolException) return

socksThrow :: SocksContext m -> SocksException -> m a
socksThrow = socksContextThrow


socksClientJustSelectMethod :: Monad m => SocksContext m -> [SocksMethod] -> m SocksMethod
socksClientJustSelectMethod ctx methods = do
    socksSend ctx $ SocksMethodRequest methods
    SocksMethodResponse mmethod <- socksRecv ctx
    case mmethod of
        Nothing -> socksThrow ctx SocksNoAcceptibleMethodsException
        Just method ->
            if method `elem` methods
            then return method
            else socksThrow ctx SocksNoAcceptibleMethodsException

socksClientJustAuthenticateUsernamePassword :: Monad m => SocksContext m -> SocksUsernamePassword -> m ()
socksClientJustAuthenticateUsernamePassword ctx creds = do
    socksSend ctx $ SocksUsernamePasswordRequest creds
    resp <- socksRecv ctx
    case resp of
        SocksUsernamePasswordResponseSuccess -> return ()
        SocksUsernamePasswordResponseFailure w -> socksThrow ctx $ SocksUsernamePasswordAuthenticationFailureException w

socksClientAuthenticateNone :: Monad m => SocksContext m -> m ()
socksClientAuthenticateNone ctx = void $ socksClientJustSelectMethod ctx [SocksMethodNone]

socksClientAuthenticateUsernamePassword :: Monad m => SocksContext m -> SocksUsernamePassword -> m ()
socksClientAuthenticateUsernamePassword ctx creds = do
    socksClientJustSelectMethod ctx [SocksMethodUsernamePassword]
    socksClientJustAuthenticateUsernamePassword ctx creds

socksClientCommand :: Monad m
                   => SocksContext m
                   -> SocksCommand
                   -> SocksEndpoint
                   -> m SocksEndpoint
socksClientCommand ctx command endpoint = do
    socksSend ctx $ SocksRequest command endpoint
    resp <- socksRecv ctx
    case resp of
        SocksResponseSuccess bound -> return bound
        SocksResponseFailure failure -> socksThrow ctx $ SocksReplyFailureException failure


socksServerJustSelectMethod :: Monad m => SocksContext m -> [SocksMethod] -> m SocksMethod
socksServerJustSelectMethod ctx preferredMethods = do
    SocksMethodRequest clientMethods <- socksRecv ctx
    case filter (`elem` preferredMethods) clientMethods of
        [] -> do
            socksSend ctx $ SocksMethodResponse Nothing
            socksThrow ctx SocksNoAcceptibleMethodsException
        (method:_) -> do
            socksSend ctx $ SocksMethodResponse (Just method)
            return method

socksServerAuthenticateNone :: Monad m => SocksContext m -> m SocksRequest
socksServerAuthenticateNone ctx = do
    socksServerJustSelectMethod ctx [SocksMethodNone]
    socksRecv ctx

socksServerGetUsernamePassword :: Monad m => SocksContext m -> m SocksUsernamePassword
socksServerGetUsernamePassword ctx = do
    socksServerJustSelectMethod ctx [SocksMethodUsernamePassword]
    SocksUsernamePasswordRequest creds <- socksRecv ctx
    return creds

socksServerUsernamePasswordSuccess :: Monad m => SocksContext m -> m SocksRequest
socksServerUsernamePasswordSuccess ctx = do
    socksSend ctx SocksUsernamePasswordResponseSuccess
    socksRecv ctx

socksServerUsernamePasswordFailure :: Monad m => SocksContext m -> m a
socksServerUsernamePasswordFailure ctx = socksServerUsernamePasswordFailure' ctx 1

socksServerUsernamePasswordFailure' :: Monad m => SocksContext m -> Word8 -> m a
socksServerUsernamePasswordFailure' ctx w = do
    socksSend ctx $ SocksUsernamePasswordResponseFailure w
    socksThrow ctx $ SocksUsernamePasswordAuthenticationFailureException w

socksServerSuccess :: Monad m => SocksContext m -> SocksEndpoint -> m ()
socksServerSuccess ctx endpoint = socksSend ctx $ SocksResponseSuccess endpoint

socksServerFailure :: Monad m => SocksContext m -> SocksReplyFailure -> m a
socksServerFailure ctx failure = do
    socksSend ctx $ SocksResponseFailure failure
    socksThrow ctx $ SocksReplyFailureException failure
