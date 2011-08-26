{-# LANGUAGE
    DeriveDataTypeable #-}
module Dewdrop
    ( Gadget(..)
    , dewdrop
    , gadgets, valid
    , gadgetsWith, Config(..), defaultConfig
    , usesRegister, usesSegment, opcode
    ) where

import System.Environment
import Control.Monad
import Control.Applicative
import Control.Exception ( throwIO, ErrorCall(..) )
import Text.Printf

import Data.Typeable ( Typeable )
import Data.Data     ( Data )

import qualified Data.ByteString as B
import qualified Data.Set        as S
import qualified Generics.SYB    as G

import Data.Elf
import Hdis86 hiding ( Config(..) )
import qualified Hdis86 as H

newtype Gadget = Gadget [Metadata]
    deriving (Eq, Ord, Typeable, Data)

instance Show Gadget where
    show (Gadget []) = "<empty Gadget>"
    show (Gadget g@(g1:_)) = printf fmt addr ++ unlines asm where
        addr = mdOffset g1
        fmt | addr > 0xffffffff = "%016x:\n"
            | otherwise         = "%08x:\n"
        asm = map (("  "++) . mdAssembly) g

data Config = Config
    { cfgSyntax  :: Syntax
    , cfgVendor  :: Vendor
    , cfgMaxSize :: Int
    } deriving (Eq, Ord, Read, Show, Typeable, Data)

defaultConfig :: Config
defaultConfig = Config SyntaxATT Intel 20

gadgetsWith :: Config -> Elf -> [Gadget]
gadgetsWith cfg elf = map Gadget $ concatMap scanSect exec where
    hcfg = intel32 {
          H.cfgSyntax  = cfgSyntax cfg
        , H.cfgVendor  = cfgVendor cfg
        , H.cfgCPUMode = case elfClass elf of
            ELFCLASS32 -> Mode32
            ELFCLASS64 -> Mode64
        }

    exec = filter ((SHF_EXECINSTR `elem`) . elfSectionFlags) $ elfSections elf

    scanSect sect = do
        let bytes = elfSectionData sect
            idxes = flip B.elemIndices bytes
        index <- idxes 0xC3 ++ map (+2) (idxes 0xC2)
        let hd = B.take (index + 1) bytes
        subseq <- B.tails $ B.drop (B.length hd - cfgMaxSize cfg) hd
        let addr =   elfSectionAddr sect
                   + fromIntegral index + 1
                   - fromIntegral (B.length subseq)
        return $ disassembleMetadata (hcfg { H.cfgOrigin = addr }) subseq

gadgets :: Elf -> [Gadget]
gadgets = gadgetsWith defaultConfig

valid :: Gadget -> Bool
valid = \(Gadget g) -> all ($ g) [(>1) . length, opcodesOk] where
    -- scoped outside the lambda, to share evaluation between calls
    badOpcodes = S.fromList [
        -- privileged or exception-raising
          Iinvalid
        , Iin,  Iinsb,  Iinsw,  Iinsd
        , Iout, Ioutsb, Ioutsw, Ioutsd
        , Iiretw, Iiretd, Iiretq
        , Isysexit, Isysret
        , Ihlt, Icli, Isti, Illdt, Ilgdt, Ilidt, Iltr
        , Ivmcall, Ivmresume, Ivmxon, Ivmxoff
        -- , Ivmlaunch, Ivmread, Ivmwrite,  -- not in udis86?
        , Ivmptrld, Ivmptrst, Ivmclear
        , Imonitor, Imwait, Ilmsw, Iinvlpg, Iswapgs
        , Iclts, Iinvd, Iwbinvd
        , Irdmsr, Iwrmsr

        -- return before end
        , Iret,  Iretf ]

    opcodesOk g = case reverse $ map (inOpcode . mdInst) g of
        (Iret : xs) -> all (`S.notMember` badOpcodes) xs
        _ -> False

dewdrop :: ([Metadata] -> Bool) -> IO ()
dewdrop wanted = do
    args@(~(elf_file:_)) <- getArgs
    when (null args) $ do
        progname <- getProgName
        throwIO $ ErrorCall ("Usage: " ++ progname ++ " ELF-FILE")
    elf <- parseElf <$> B.readFile elf_file
    mapM_ print . filter (\g@(Gadget xs) -> valid g && wanted xs) . gadgets $ elf

hasSub :: (Typeable a, Eq a, Data b) => a -> b -> Bool
hasSub x = not . null . G.listify (== x)

usesRegister :: GPR -> Metadata -> Bool
usesRegister = hasSub

usesSegment :: Segment -> Metadata -> Bool
usesSegment = hasSub

opcode :: Metadata -> Opcode
opcode = inOpcode . mdInst
