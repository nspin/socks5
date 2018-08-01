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


socksClientJustSelectMethod :: Monad m => [SocksMethod] -> SocksContext m -> m SocksMethod
socksClientJustSelectMethod methods ctx = do
    socksSend ctx $ SocksMethodRequest methods
    SocksMethodResponse mmethod <- socksRecv ctx
    case mmethod of
        Nothing -> socksThrow ctx SocksNoAcceptibleMethodsException
        Just method ->
            if method `elem` methods
            then return method
            else socksThrow ctx SocksNoAcceptibleMethodsException

socksServerJustSelectMethod :: Monad m => [SocksMethod] -> SocksContext m -> m SocksMethod
socksServerJustSelectMethod preferredMethods ctx = do
    SocksMethodRequest clientMethods <- socksRecv ctx
    case filter (`elem` preferredMethods) clientMethods of
        [] -> do
            socksSend ctx $ SocksMethodResponse Nothing
            socksThrow ctx SocksNoAcceptibleMethodsException
        (method:_) -> do
            socksSend ctx $ SocksMethodResponse (Just method)
            return method

socksClientJustAuthenticateWithUsernamePassword :: Monad m => SocksUsernamePassword -> SocksContext m -> m ()
socksClientJustAuthenticateWithUsernamePassword creds ctx = do
    socksSend ctx $ SocksUsernamePasswordRequest creds
    resp <- socksRecv ctx
    case resp of
        SocksUsernamePasswordResponseSuccess -> return ()
        SocksUsernamePasswordResponseFailure w -> socksThrow ctx $ SocksUsernamePasswordAuthenticationFailureException w

socksServerJustAuthenticateWithUsernamePassword :: Monad m => SocksServerUsernamePasswordGuard m -> SocksContext m -> m ()
socksServerJustAuthenticateWithUsernamePassword guard ctx = do
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


socksClientAuthenticate :: Monad m => SocksClientAuthenticationPreference -> SocksContext m -> m ()
socksClientAuthenticate pref ctx = case pref of
    SocksClientAuthenticationPreferenceNone ->
        void $ socksClientJustSelectMethod [SocksMethodNone] ctx
    SocksClientAuthenticationPreferenceUsernamePassword creds ->
        go creds [SocksMethodUsernamePassword]
    SocksClientAuthenticationPreferenceNoneOrUsernamePassword creds ->
        go creds [SocksMethodNone, SocksMethodUsernamePassword]
    SocksClientAuthenticationPreferenceUsernamePasswordOrNone creds ->
        go creds [SocksMethodUsernamePassword, SocksMethodNone]
  where
    go creds methods = do
        method <- socksClientJustSelectMethod methods ctx
        case method of
            SocksMethodNone -> return ()
            SocksMethodUsernamePassword -> socksClientJustAuthenticateWithUsernamePassword creds ctx

socksServerAuthenticate :: Monad m => SocksServerAuthenticationPreference m -> SocksContext m -> m ()
socksServerAuthenticate pref ctx = do
  case pref of
    SocksServerAuthenticationPreferenceNone ->
        void $ socksServerJustSelectMethod [SocksMethodNone] ctx
    SocksServerAuthenticationPreferenceUsernamePassword rule ->
        go rule [SocksMethodUsernamePassword]
    SocksServerAuthenticationPreferenceNoneOrUsernamePassword rule ->
        go rule [SocksMethodNone, SocksMethodUsernamePassword]
    SocksServerAuthenticationPreferenceUsernamePasswordOrNone rule ->
        go rule [SocksMethodUsernamePassword, SocksMethodNone]
  where
    go rule methods = do
        method <- socksServerJustSelectMethod methods ctx
        case method of
            SocksMethodNone -> return ()
            SocksMethodUsernamePassword -> socksServerJustAuthenticateWithUsernamePassword rule ctx


socksClientJustCommand :: Monad m
                       => SocksCommand
                       -> SocksEndpoint
                       -> SocksContext m
                       -> m SocksEndpoint
socksClientJustCommand command endpoint ctx = do
    socksSend ctx $ SocksRequest command endpoint
    SocksResponse resp <- socksRecv ctx
    case resp of
        Left failure -> socksThrow ctx $ SocksReplyFailureException failure
        Right bound -> return bound

socksClientCommand :: Monad m
                   => SocksClientAuthenticationPreference
                   -> SocksCommand
                   -> SocksEndpoint
                   -> SocksContext m
                   -> m SocksEndpoint
socksClientCommand pref command endpoint = do
    socksClientAuthenticate pref
    socksClientJustCommand command endpoint
