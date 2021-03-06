{-# LANGUAGE
    DeriveDataTypeable #-}

-- | Analyze the ROP gadgets in an ELF binary.
--
-- Use this module if you need more control, or integration with a larger
-- program. The module "Dewdrop" provides a simpler way to put together a
-- standalone gadget finder.
module Dewdrop.Analyze
    ( -- * Finding gadgets
      Gadget(..)
    , gadgets, valid

      -- * Configuring the gadget finder
    , Config(..), defaultConfig
    , gadgetsWith
    ) where

import Text.Printf

import Data.Typeable ( Typeable )
import Data.Data     ( Data )

import qualified Data.ByteString as B
import qualified Data.Set        as S

import Data.Elf
import Hdis86 hiding ( Config(..) )
import qualified Hdis86 as H

-- | A sequence of instructions, each with metadata.
--
-- The @'Show'@ instance produces assembly code with labeled offsets,
-- so you can @'print'@ these directly.
newtype Gadget = Gadget [Metadata]
    deriving (Eq, Ord, Typeable, Data)

instance Show Gadget where
    show (Gadget []) = "<empty Gadget>"
    show (Gadget g@(g1:_)) = printf fmt addr ++ unlines asm where
        addr = mdOffset g1
        fmt | addr > 0xffffffff = "%016x:\n"
            | otherwise         = "%08x:\n"
        asm = map (("  "++) . mdAssembly) g

-- | Configuration of the gadget finder.
data Config = Config
    { cfgSyntax  :: Syntax  -- ^ Assembly syntax for display
    , cfgVendor  :: Vendor  -- ^ CPU vendor; affects decoding of a
                            --   few instructions
    , cfgMaxSize :: Int     -- ^ Maximum size of a gadget, in bytes
    } deriving (Eq, Ord, Read, Show, Typeable, Data)

-- | Default configuration of the gadget finder.
defaultConfig :: Config
defaultConfig = Config SyntaxATT Intel 20

-- | Find possible gadgets, using a custom configuration.
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

-- | Find possible gadgets.
--
-- You can filter these further using @'valid'@ or other tests.
gadgets :: Elf -> [Gadget]
gadgets = gadgetsWith defaultConfig

-- | Rejects gadgets which are probably not useful for return-oriented
-- programming.  This includes gadgets containing invalid or privileged
-- instructions.
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
