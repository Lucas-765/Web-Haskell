{-# LANGUAGE OverloadedStrings #-}

module Banco (Banco, iniciarBanco, comBanco) where

import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Servant (Handler)

-- | Uma única conexão protegida por MVar: uma requisição por vez usa o banco.
type Banco = MVar Connection

comBanco :: Banco -> (Connection -> IO a) -> Handler a
comBanco banco acao = liftIO (withMVar banco acao)

iniciarBanco :: IO Banco
iniciarBanco = do
  conn <- open "studyhub.db"
  mapM_ (execute_ conn) esquema
  newMVar conn

esquema :: [Query]
esquema =
  [ "PRAGMA foreign_keys = ON"
  , "CREATE TABLE IF NOT EXISTS usuarios (\
    \ id INTEGER PRIMARY KEY AUTOINCREMENT,\
    \ nome TEXT NOT NULL,\
    \ email TEXT NOT NULL UNIQUE,\
    \ senha_hash TEXT NOT NULL,\
    \ instituicao TEXT NOT NULL DEFAULT '',\
    \ curso TEXT NOT NULL DEFAULT '',\
    \ semestre INTEGER NOT NULL DEFAULT 1,\
    \ bio TEXT NOT NULL DEFAULT '')"
  , "CREATE TABLE IF NOT EXISTS grupos (\
    \ id INTEGER PRIMARY KEY AUTOINCREMENT,\
    \ titulo TEXT NOT NULL,\
    \ descricao TEXT NOT NULL,\
    \ instituicao TEXT NOT NULL,\
    \ modalidade TEXT NOT NULL,\
    \ tags TEXT NOT NULL,\
    \ link_externo TEXT NOT NULL,\
    \ entrada TEXT NOT NULL,\
    \ dono_id INTEGER NOT NULL REFERENCES usuarios(id))"
  , "CREATE TABLE IF NOT EXISTS membros (\
    \ grupo_id INTEGER NOT NULL REFERENCES grupos(id) ON DELETE CASCADE,\
    \ usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,\
    \ papel TEXT NOT NULL,\
    \ status TEXT NOT NULL,\
    \ PRIMARY KEY (grupo_id, usuario_id))"
  , "CREATE TABLE IF NOT EXISTS encontros (\
    \ id INTEGER PRIMARY KEY AUTOINCREMENT,\
    \ grupo_id INTEGER NOT NULL REFERENCES grupos(id) ON DELETE CASCADE,\
    \ titulo TEXT NOT NULL,\
    \ data_hora TEXT NOT NULL,\
    \ local_ou_link TEXT NOT NULL,\
    \ vagas INTEGER NOT NULL DEFAULT 0)"
  , "CREATE TABLE IF NOT EXISTS presencas (\
    \ encontro_id INTEGER NOT NULL REFERENCES encontros(id) ON DELETE CASCADE,\
    \ usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,\
    \ PRIMARY KEY (encontro_id, usuario_id))"
  , "CREATE TABLE IF NOT EXISTS materiais (\
    \ id INTEGER PRIMARY KEY AUTOINCREMENT,\
    \ grupo_id INTEGER NOT NULL REFERENCES grupos(id) ON DELETE CASCADE,\
    \ autor_id INTEGER NOT NULL REFERENCES usuarios(id),\
    \ titulo TEXT NOT NULL,\
    \ url TEXT NOT NULL,\
    \ criado_em TEXT NOT NULL DEFAULT (datetime('now')))"
  , "CREATE TABLE IF NOT EXISTS avisos (\
    \ id INTEGER PRIMARY KEY AUTOINCREMENT,\
    \ grupo_id INTEGER NOT NULL REFERENCES grupos(id) ON DELETE CASCADE,\
    \ autor_id INTEGER NOT NULL REFERENCES usuarios(id),\
    \ texto TEXT NOT NULL,\
    \ criado_em TEXT NOT NULL DEFAULT (datetime('now')))"
  ]