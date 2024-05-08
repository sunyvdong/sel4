{-# LANGUAGE CPP #-}
{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module Paths_capDL_tool (
    version,
    getBinDir, getLibDir, getDynLibDir, getDataDir, getLibexecDir,
    getDataFileName, getSysconfDir
  ) where


import qualified Control.Exception as Exception
import qualified Data.List as List
import Data.Version (Version(..))
import System.Environment (getEnv)
import Prelude


#if defined(VERSION_base)

#if MIN_VERSION_base(4,0,0)
catchIO :: IO a -> (Exception.IOException -> IO a) -> IO a
#else
catchIO :: IO a -> (Exception.Exception -> IO a) -> IO a
#endif

#else
catchIO :: IO a -> (Exception.IOException -> IO a) -> IO a
#endif
catchIO = Exception.catch

version :: Version
version = Version [1,0,0,1] []

getDataFileName :: FilePath -> IO FilePath
getDataFileName name = do
  dir <- getDataDir
  return (dir `joinFileName` name)

getBinDir, getLibDir, getDynLibDir, getDataDir, getLibexecDir, getSysconfDir :: IO FilePath



bindir, libdir, dynlibdir, datadir, libexecdir, sysconfdir :: FilePath
bindir     = "/home/sunyvdong/sel4/20240508/sel4-tutorials-manifest/tutorial_build/capDL-tool/.stack-work/install/x86_64-linux-tinfo6-libc6-pre232/b33b8115abd54f93942c981b4c4732f66f4fd81b4680a1308593fb762a732c50/9.2.8/bin"
libdir     = "/home/sunyvdong/sel4/20240508/sel4-tutorials-manifest/tutorial_build/capDL-tool/.stack-work/install/x86_64-linux-tinfo6-libc6-pre232/b33b8115abd54f93942c981b4c4732f66f4fd81b4680a1308593fb762a732c50/9.2.8/lib/x86_64-linux-ghc-9.2.8/capDL-tool-1.0.0.1-FnWIWtcAkIh4EyQepY0tJ-parse-capDL"
dynlibdir  = "/home/sunyvdong/sel4/20240508/sel4-tutorials-manifest/tutorial_build/capDL-tool/.stack-work/install/x86_64-linux-tinfo6-libc6-pre232/b33b8115abd54f93942c981b4c4732f66f4fd81b4680a1308593fb762a732c50/9.2.8/lib/x86_64-linux-ghc-9.2.8"
datadir    = "/home/sunyvdong/sel4/20240508/sel4-tutorials-manifest/tutorial_build/capDL-tool/.stack-work/install/x86_64-linux-tinfo6-libc6-pre232/b33b8115abd54f93942c981b4c4732f66f4fd81b4680a1308593fb762a732c50/9.2.8/share/x86_64-linux-ghc-9.2.8/capDL-tool-1.0.0.1"
libexecdir = "/home/sunyvdong/sel4/20240508/sel4-tutorials-manifest/tutorial_build/capDL-tool/.stack-work/install/x86_64-linux-tinfo6-libc6-pre232/b33b8115abd54f93942c981b4c4732f66f4fd81b4680a1308593fb762a732c50/9.2.8/libexec/x86_64-linux-ghc-9.2.8/capDL-tool-1.0.0.1"
sysconfdir = "/home/sunyvdong/sel4/20240508/sel4-tutorials-manifest/tutorial_build/capDL-tool/.stack-work/install/x86_64-linux-tinfo6-libc6-pre232/b33b8115abd54f93942c981b4c4732f66f4fd81b4680a1308593fb762a732c50/9.2.8/etc"

getBinDir     = catchIO (getEnv "capDL_tool_bindir")     (\_ -> return bindir)
getLibDir     = catchIO (getEnv "capDL_tool_libdir")     (\_ -> return libdir)
getDynLibDir  = catchIO (getEnv "capDL_tool_dynlibdir")  (\_ -> return dynlibdir)
getDataDir    = catchIO (getEnv "capDL_tool_datadir")    (\_ -> return datadir)
getLibexecDir = catchIO (getEnv "capDL_tool_libexecdir") (\_ -> return libexecdir)
getSysconfDir = catchIO (getEnv "capDL_tool_sysconfdir") (\_ -> return sysconfdir)




joinFileName :: String -> String -> FilePath
joinFileName ""  fname = fname
joinFileName "." fname = fname
joinFileName dir ""    = dir
joinFileName dir fname
  | isPathSeparator (List.last dir) = dir ++ fname
  | otherwise                       = dir ++ pathSeparator : fname

pathSeparator :: Char
pathSeparator = '/'

isPathSeparator :: Char -> Bool
isPathSeparator c = c == '/'
