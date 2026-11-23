{-# LANGUAGE DeriveGeneric #-}

module Tipos where

import Data.Aeson
import Data.Char (isLower, toLower)
import Data.Int (Int64)
import Data.Text (Text)
import Database.SQLite.Simple (FromRow (..), field)
import GHC.Generics (Generic)
import Servant.Auth.Server (FromJWT, ToJWT)

-- | Remove o prefixo em minúsculas do campo e deixa a primeira letra minúscula.
-- Ex.: usuarioNome -> "nome", giTitulo -> "titulo", encontroDataHora -> "dataHora".
opcoes :: Options
opcoes = defaultOptions {fieldLabelModifier = minuscula . dropWhile isLower}
  where
    minuscula [] = []
    minuscula (c : cs) = toLower c : cs

-- ---------------------------------------------------------------
-- Sessão (conteúdo do JWT)
-- ---------------------------------------------------------------

newtype Sessao = Sessao {sessaoId :: Int64} deriving (Show, Generic)

instance ToJSON Sessao
instance FromJSON Sessao
instance ToJWT Sessao
instance FromJWT Sessao

-- ---------------------------------------------------------------
-- Saídas (o que a API devolve)
-- ---------------------------------------------------------------

data Usuario = Usuario
  { usuarioId :: Int64
  , usuarioNome :: Text
  , usuarioEmail :: Text
  , usuarioInstituicao :: Text
  , usuarioCurso :: Text
  , usuarioSemestre :: Int
  , usuarioBio :: Text
  }
  deriving (Show, Generic)

data Grupo = Grupo
  { grupoId :: Int64
  , grupoTitulo :: Text
  , grupoDescricao :: Text
  , grupoInstituicao :: Text
  , grupoModalidade :: Text
  , grupoTags :: Text
  , grupoLink :: Text
  , grupoEntrada :: Text
  , grupoDonoId :: Int64
  , grupoMembros :: Int
  }
  deriving (Show, Generic)

data Membro = Membro
  { membroUsuarioId :: Int64
  , membroNome :: Text
  , membroPapel :: Text
  , membroStatus :: Text
  }
  deriving (Show, Generic)

data Encontro = Encontro
  { encontroId :: Int64
  , encontroGrupoId :: Int64
  , encontroTitulo :: Text
  , encontroDataHora :: Text
  , encontroLocal :: Text
  , encontroVagas :: Int
  , encontroConfirmados :: Int
  }
  deriving (Show, Generic)

data Material = Material
  { materialId :: Int64
  , materialTitulo :: Text
  , materialUrl :: Text
  , materialAutor :: Text
  , materialCriadoEm :: Text
  }
  deriving (Show, Generic)

data Aviso = Aviso
  { avisoId :: Int64
  , avisoTexto :: Text
  , avisoAutor :: Text
  , avisoCriadoEm :: Text
  }
  deriving (Show, Generic)

newtype Token = Token {tokenToken :: Text} deriving (Show, Generic)

newtype Status = Status {statusStatus :: Text} deriving (Show, Generic)

-- ---------------------------------------------------------------
-- Entradas (o que a API recebe)
-- ---------------------------------------------------------------

data Cadastro = Cadastro
  { cadastroNome :: Text
  , cadastroEmail :: Text
  , cadastroSenha :: Text
  , cadastroInstituicao :: Text
  , cadastroCurso :: Text
  , cadastroSemestre :: Int
  }
  deriving (Show, Generic)

data Login = Login
  { loginEmail :: Text
  , loginSenha :: Text
  }
  deriving (Show, Generic)

data PerfilIn = PerfilIn
  { perfilNome :: Text
  , perfilInstituicao :: Text
  , perfilCurso :: Text
  , perfilSemestre :: Int
  , perfilBio :: Text
  }
  deriving (Show, Generic)

data GrupoIn = GrupoIn
  { giTitulo :: Text
  , giDescricao :: Text
  , giInstituicao :: Text
  , giModalidade :: Text
  , giTags :: Text
  , giLink :: Text
  , giEntrada :: Text
  }
  deriving (Show, Generic)

data MembroIn = MembroIn
  { miPapel :: Text
  , miStatus :: Text
  }
  deriving (Show, Generic)

data EncontroIn = EncontroIn
  { eiTitulo :: Text
  , eiDataHora :: Text
  , eiLocal :: Text
  , eiVagas :: Int
  }
  deriving (Show, Generic)

data MaterialIn = MaterialIn
  { mtTitulo :: Text
  , mtUrl :: Text
  }
  deriving (Show, Generic)

newtype AvisoIn = AvisoIn {avTexto :: Text} deriving (Show, Generic)

-- ---------------------------------------------------------------
-- Instâncias JSON
-- ---------------------------------------------------------------

instance ToJSON Usuario where toJSON = genericToJSON opcoes
instance ToJSON Grupo where toJSON = genericToJSON opcoes
instance ToJSON Membro where toJSON = genericToJSON opcoes
instance ToJSON Encontro where toJSON = genericToJSON opcoes
instance ToJSON Material where toJSON = genericToJSON opcoes
instance ToJSON Aviso where toJSON = genericToJSON opcoes
instance ToJSON Token where toJSON = genericToJSON opcoes
instance ToJSON Status where toJSON = genericToJSON opcoes

instance FromJSON Cadastro where parseJSON = genericParseJSON opcoes
instance FromJSON Login where parseJSON = genericParseJSON opcoes
instance FromJSON PerfilIn where parseJSON = genericParseJSON opcoes
instance FromJSON GrupoIn where parseJSON = genericParseJSON opcoes
instance FromJSON MembroIn where parseJSON = genericParseJSON opcoes
instance FromJSON EncontroIn where parseJSON = genericParseJSON opcoes
instance FromJSON MaterialIn where parseJSON = genericParseJSON opcoes
instance FromJSON AvisoIn where parseJSON = genericParseJSON opcoes

-- ---------------------------------------------------------------
-- Leitura de linhas do SQLite (a ordem das colunas do SELECT importa)
-- ---------------------------------------------------------------

instance FromRow Usuario where
  fromRow = Usuario <$> field <*> field <*> field <*> field <*> field <*> field <*> field

instance FromRow Grupo where
  fromRow =
    Grupo <$> field <*> field <*> field <*> field <*> field
      <*> field <*> field <*> field <*> field <*> field

instance FromRow Membro where
  fromRow = Membro <$> field <*> field <*> field <*> field

instance FromRow Encontro where
  fromRow = Encontro <$> field <*> field <*> field <*> field <*> field <*> field <*> field

instance FromRow Material where
  fromRow = Material <$> field <*> field <*> field <*> field <*> field

instance FromRow Aviso where
  fromRow = Aviso <$> field <*> field <*> field <*> field