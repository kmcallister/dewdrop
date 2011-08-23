import System.Environment
import Control.Monad
import Control.Applicative
import Numeric
import Data.List

import qualified Generics.SYB    as G
import qualified Data.ByteString as B
import qualified Data.Set        as S

import Data.Elf
import Hdis86

type Gadget = [Metadata]

execSections :: Elf -> [ElfSection]
execSections = filter ((SHF_EXECINSTR `elem`) . elfSectionFlags) . elfSections

gadgets :: Elf -> [Gadget]
gadgets = concatMap scanSect . execSections where
    scanSect sect = do
        let bytes = elfSectionData sect
        index <- B.elemIndices 0xC3 $ bytes
        let hd = B.take (index + 1) bytes
            maxCandidate = 20
        subseq <- B.tails $ B.drop (B.length hd - maxCandidate) hd
        let addr =   elfSectionAddr sect
                   + fromIntegral index
                   - fromIntegral (B.length subseq)
            cfg  = amd64 { cfgOrigin = addr
                         , cfgSyntax = SyntaxATT }
        return (disassembleMetadata cfg subseq)

formatOne :: Gadget -> String
formatOne g@(g1:_)
    = showHex (mdOffset g1) $ (":\n" ++) $
      intercalate "\n" $
      map (("  "++) . mdAssembly) g
formatOne [] = error "empty gadget"

valid :: Gadget -> Bool
valid = \g -> all ($ g) [(>1) . length, opcodesOk, noStack]
    where
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

            -- stack manipulation
            , Ipush, Ipusha, Ipushad, Ipushfw, Ipushfd, Ipushfq
            , Ipop,  Ipopa,  Ipopad,  Ipopfw,  Ipopfd,  Ipopfq
            , Iret,  Iretf ]

        opcodesOk g = case reverse $ map (inOpcode . mdInst) g of
            (Iret : xs) -> all (`S.notMember` badOpcodes) xs
            _ -> False

        noStack = null . G.listify (== RSP)

main :: IO ()
main = do
    args@(~[elf_file]) <- getArgs
    when (null args) $
        error "Usage: findROP ELF-FILE"
    elf <- parseElf <$> B.readFile elf_file
    let found = filter valid . gadgets $ elf
    mapM_ (putStrLn . formatOne) found
