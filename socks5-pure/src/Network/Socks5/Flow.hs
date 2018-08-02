{-# LANGUAGE RankNTypes #-}

module Network.Socks5.Flow
    ( SocksException(..)

    , SocksContext(..)
    , socksSend
    , socksRecv
    , socksThrow

    , socksClientAuthenticate
    , socksClientJustSelectMethod
    , socksClientJustAuthenticateWithUsernamePassword

    , socksServerAuthenticate
    , socksServerJustSelectMethod
    , socksServerJustAuthenticateWithUsernamePassword

    , SocksClientAuthenticationPreference(..)
    , SocksServerAuthenticationPreference(..)
    , SocksServerUsernamePasswordGuard

    , socksClientCommand
    , socksClientJustCommand

    ) where

import Control.Exception (Exception)
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.Serialize
import Data.Word (Word8)
import Network.Socks5.Types


data SocksException =
      SocksProtocolException String -- ^ deserialization failure
    | SocksNoAcceptibleMethodsException
    | SocksUsernamePasswordAuthenticationFailureException Word8
    | SocksReplyFailureException SocksReplyFailure
    | SocksInternalError String
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

socksClientJustAuthenticateWithUsernamePassword :: Monad m => SocksContext m -> SocksUsernamePassword -> m ()
socksClientJustAuthenticateWithUsernamePassword ctx creds = do
    socksSend ctx $ SocksUsernamePasswordRequest creds
    resp <- socksRecv ctx
    case resp of
        SocksUsernamePasswordResponseSuccess -> return ()
        SocksUsernamePasswordResponseFailure w -> socksThrow ctx $ SocksUsernamePasswordAuthenticationFailureException w

socksServerJustAuthenticateWithUsernamePassword :: Monad m => SocksContext m -> SocksServerUsernamePasswordGuard m -> m ()
socksServerJustAuthenticateWithUsernamePassword ctx guard = do
    SocksUsernamePasswordRequest creds <- socksRecv ctx
    r <- guard creds
    case r of
        Nothing -> socksSend ctx SocksUsernamePasswordResponseSuccess
        Just w -> do
            socksSend ctx $ SocksUsernamePasswordResponseFailure w
            socksThrow ctx $ SocksUsernamePasswordAuthenticationFailureException w


data SocksClientAuthenticationPreference =
      SocksClientAuthenticationPreferenceNone
    | SocksClientAuthenticationPreferenceUsernamePassword SocksUsernamePassword
    | SocksClientAuthenticationPreferenceNoneOrUsernamePassword SocksUsernamePassword
    | SocksClientAuthenticationPreferenceUsernamePasswordOrNone SocksUsernamePassword
    deriving (Show, Eq)

data SocksServerAuthenticationPreference m =
      SocksServerAuthenticationPreferenceNone
    | SocksServerAuthenticationPreferenceUsernamePassword (SocksServerUsernamePasswordGuard m)
    | SocksServerAuthenticationPreferenceNoneOrUsernamePassword (SocksServerUsernamePasswordGuard m)
    | SocksServerAuthenticationPreferenceUsernamePasswordOrNone (SocksServerUsernamePasswordGuard m)

type SocksServerUsernamePasswordGuard m = SocksUsernamePassword -> m (Maybe Word8)


socksClientAuthenticate :: Monad m => SocksContext m -> SocksClientAuthenticationPreference -> m ()
socksClientAuthenticate ctx pref = case pref of
    SocksClientAuthenticationPreferenceNone ->
        void $ socksClientJustSelectMethod ctx [SocksMethodNone]
    SocksClientAuthenticationPreferenceUsernamePassword creds ->
        go creds [SocksMethodUsernamePassword]
    SocksClientAuthenticationPreferenceNoneOrUsernamePassword creds ->
        go creds [SocksMethodNone, SocksMethodUsernamePassword]
    SocksClientAuthenticationPreferenceUsernamePasswordOrNone creds ->
        go creds [SocksMethodUsernamePassword, SocksMethodNone]
  where
    go creds methods = do
        method <- socksClientJustSelectMethod ctx methods
        case method of
            SocksMethodNone -> return ()
            SocksMethodUsernamePassword -> socksClientJustAuthenticateWithUsernamePassword ctx creds

socksServerAuthenticate :: Monad m => SocksContext m -> SocksServerAuthenticationPreference m -> m ()
socksServerAuthenticate ctx pref = do
  case pref of
    SocksServerAuthenticationPreferenceNone ->
        void $ socksServerJustSelectMethod ctx [SocksMethodNone]
    SocksServerAuthenticationPreferenceUsernamePassword rule ->
        go rule [SocksMethodUsernamePassword]
    SocksServerAuthenticationPreferenceNoneOrUsernamePassword rule ->
        go rule [SocksMethodNone, SocksMethodUsernamePassword]
    SocksServerAuthenticationPreferenceUsernamePasswordOrNone rule ->
        go rule [SocksMethodUsernamePassword, SocksMethodNone]
  where
    go rule methods = do
        method <- socksServerJustSelectMethod ctx methods
        case method of
            SocksMethodNone -> return ()
            SocksMethodUsernamePassword -> socksServerJustAuthenticateWithUsernamePassword ctx rule


socksClientJustCommand :: Monad m
                       => SocksContext m
                       -> SocksCommand
                       -> SocksEndpoint
                       -> m SocksEndpoint
socksClientJustCommand ctx command endpoint = do
    socksSend ctx $ SocksRequest command endpoint
    SocksResponse resp <- socksRecv ctx
    case resp of
        Left failure -> socksThrow ctx $ SocksReplyFailureException failure
        Right bound -> return bound

socksClientCommand :: Monad m
                   => SocksContext m
                   -> SocksClientAuthenticationPreference
                   -> SocksCommand
                   -> SocksEndpoint
                   -> m SocksEndpoint
socksClientCommand ctx pref command endpoint = do
    socksClientAuthenticate ctx pref
    socksClientJustCommand ctx command endpoint
