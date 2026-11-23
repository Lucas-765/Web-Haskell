{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}

module Api (API, api, servidor) where

import Banco
import Control.Exception (try)
import Control.Monad (unless, when)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)
import Data.Maybe (fromMaybe)
import Crypto.BCrypt
  (hashPasswordUsingPolicy, 
  slowerBcryptHashingPolicy, 
  validatePassword)
import Data.Proxy (Proxy (..))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (addUTCTime, getCurrentTime)
import Database.SQLite.Simple
import Servant
import Servant.Auth (Auth, JWT)
import Servant.Auth.Server (AuthResult (..), JWTSettings, makeJWT, throwAll)
import Tipos

-- ---------------------------------------------------------------
-- Rotas
-- ---------------------------------------------------------------

-- | Rotas que exigem login (JWT no cabeçalho Authorization: Bearer ...).
type Protegida =
       -- Fase 2: perfil
       "perfil" :> Get '[JSON] Usuario
  :<|> "perfil" :> ReqBody '[JSON] PerfilIn :> Put '[JSON] Usuario
       -- Fase 2/3: grupos
  :<|> "grupos"
         :> QueryParam "busca" Text
         :> QueryParam "tag" Text
         :> QueryParam "instituicao" Text
         :> QueryParam "modalidade" Text
         :> QueryParam "pagina" Int
         :> QueryParam "limite" Int
         :> Get '[JSON] [Grupo]
  :<|> "grupos" :> Capture "id" Int64 :> Get '[JSON] Grupo
  :<|> "grupos" :> ReqBody '[JSON] GrupoIn :> PostCreated '[JSON] Grupo
  :<|> "grupos" :> Capture "id" Int64 :> ReqBody '[JSON] GrupoIn :> Put '[JSON] Grupo
  :<|> "grupos" :> Capture "id" Int64 :> Delete '[JSON] Status
       -- Fase 3: membros
  :<|> "grupos" :> Capture "id" Int64 :> "entrar" :> Post '[JSON] Status
  :<|> "grupos" :> Capture "id" Int64 :> "membros" :> Get '[JSON] [Membro]
  :<|> "grupos" :> Capture "id" Int64 :> "membros" :> Capture "uid" Int64
         :> ReqBody '[JSON] MembroIn :> Put '[JSON] Status
  :<|> "grupos" :> Capture "id" Int64 :> "membros" :> Capture "uid" Int64 :> Delete '[JSON] Status
       -- Fase 4: encontros
  :<|> "grupos" :> Capture "id" Int64 :> "encontros" :> Get '[JSON] [Encontro]
  :<|> "grupos" :> Capture "id" Int64 :> "encontros"
         :> ReqBody '[JSON] EncontroIn :> PostCreated '[JSON] Encontro
  :<|> "encontros" :> Capture "id" Int64 :> "presenca" :> Post '[JSON] Status
  :<|> "encontros" :> Capture "id" Int64 :> "presenca" :> Delete '[JSON] Status
       -- Fase 5: materiais e avisos
  :<|> "grupos" :> Capture "id" Int64 :> "materiais" :> Get '[JSON] [Material]
  :<|> "grupos" :> Capture "id" Int64 :> "materiais"
         :> ReqBody '[JSON] MaterialIn :> PostCreated '[JSON] Material
  :<|> "grupos" :> Capture "id" Int64 :> "avisos" :> Get '[JSON] [Aviso]
  :<|> "grupos" :> Capture "id" Int64 :> "avisos"
         :> ReqBody '[JSON] AvisoIn :> PostCreated '[JSON] Aviso

type API =
       -- Fase 1: cadastro e login (públicos)
       "cadastro" :> ReqBody '[JSON] Cadastro :> PostCreated '[JSON] Usuario
  :<|> "login" :> ReqBody '[JSON] Login :> Post '[JSON] Token
  :<|> Auth '[JWT] Sessao :> Protegida
       -- Front end
  :<|> Raw

api :: Proxy API
api = Proxy

servidor :: Banco -> JWTSettings -> Server API
servidor banco jwt =
  cadastrar banco
    :<|> login banco jwt
    :<|> protegido banco
    :<|> serveDirectoryFileServer "static"

protegido :: Banco -> AuthResult Sessao -> Server Protegida
protegido banco (Authenticated (Sessao uid)) =
       verPerfil banco uid
  :<|> editarPerfil banco uid
  :<|> listarGrupos banco uid
  :<|> verGrupo banco uid
  :<|> criarGrupo banco uid
  :<|> atualizarGrupo banco uid
  :<|> excluirGrupo banco uid
  :<|> entrarGrupo banco uid
  :<|> listarMembros banco uid
  :<|> atualizarMembro banco uid
  :<|> removerMembro banco uid
  :<|> listarEncontros banco uid
  :<|> criarEncontro banco uid
  :<|> confirmarPresenca banco uid
  :<|> cancelarPresenca banco uid
  :<|> listarMateriais banco uid
  :<|> criarMaterial banco uid
  :<|> listarAvisos banco uid
  :<|> criarAviso banco uid
protegido _ _ = throwAll err401 {errBody = "Nao autenticado"}

-- ---------------------------------------------------------------
-- Utilidades
-- ---------------------------------------------------------------

erro :: ServerError -> BL.ByteString -> Handler a
erro e msg = throwError e {errBody = msg}

naoEncontrado :: Handler a
naoEncontrado = erro err404 "Nao encontrado"

primeiro :: [a] -> Handler a
primeiro (x : _) = pure x
primeiro [] = naoEncontrado

-- | Recebe pares (condição de erro, mensagem) e lança 400 no primeiro que falhar.
validar :: [(Bool, BL.ByteString)] -> Handler ()
validar [] = pure ()
validar ((True, msg) : _) = erro err400 msg
validar (_ : resto) = validar resto

tentar :: IO a -> IO (Either SQLError a)
tentar = try

normalizarEmail :: Text -> Text
normalizarEmail = T.toLower . T.strip

normalizarTags :: Text -> Text
normalizarTags =
  T.intercalate ","
    . filter (not . T.null)
    . map (T.toLower . T.strip)
    . T.splitOn ","

-- | Devolve (papel, status) de um usuário em um grupo, se ele participa.
papelDe :: Connection -> Int64 -> Int64 -> IO (Maybe (Text, Text))
papelDe conn gid uid = do
  r <-
    query
      conn
      "SELECT papel, status FROM membros WHERE grupo_id = ? AND usuario_id = ?"
      (gid, uid)
  pure $ case r of
    (x : _) -> Just x
    [] -> Nothing

-- | Exige que o usuário seja membro ATIVO do grupo; devolve o papel dele.
exigirAtivo :: Banco -> Int64 -> Int64 -> Handler Text
exigirAtivo banco gid uid = do
  p <- comBanco banco $ \c -> papelDe c gid uid
  case p of
    Just (papel, "ativo") -> pure papel
    _ -> erro err403 "Apenas membros do grupo"

exigirPapel :: [Text] -> Banco -> Int64 -> Int64 -> Handler ()
exigirPapel permitidos banco gid uid = do
  papel <- exigirAtivo banco gid uid
  unless (papel `elem` permitidos) $ erro err403 "Sem permissao"

-- ---------------------------------------------------------------
-- Fase 1: cadastro e login
-- ---------------------------------------------------------------

cadastrar :: Banco -> Cadastro -> Handler Usuario
cadastrar banco c = do
  let email = normalizarEmail (cadastroEmail c)
  validar
    [ (T.null (T.strip (cadastroNome c)), "Nome obrigatorio")
    , (not ("@" `T.isInfixOf` email), "Email invalido")
    , (T.length (cadastroSenha c) < 8, "A senha precisa ter pelo menos 8 caracteres")
    ]
  mh <- liftIO (hashPasswordUsingPolicy slowerBcryptHashingPolicy (TE.encodeUtf8 (cadastroSenha c)))
  h <- maybe (erro err500 "Falha ao proteger a senha") pure mh
  r <- comBanco banco $ \conn -> tentar $ do
    execute
      conn
      "INSERT INTO usuarios (nome, email, senha_hash, instituicao, curso, semestre) \
      \VALUES (?,?,?,?,?,?)"
      ( T.strip (cadastroNome c)
      , email
      , TE.decodeUtf8 h
      , cadastroInstituicao c
      , cadastroCurso c
      , cadastroSemestre c
      )
    lastInsertRowId conn
  case r of
    Left _ -> erro err409 "Email ja cadastrado"
    Right i -> verPerfil banco i

login :: Banco -> JWTSettings -> Login -> Handler Token
login banco jwt (Login email senha) = do
  r <- comBanco banco $ \c ->
    query c "SELECT id, senha_hash FROM usuarios WHERE email = ?" (Only (normalizarEmail email))
  case r of
    [(i, h)]
      | validatePassword (TE.encodeUtf8 h) (TE.encodeUtf8 senha) -> do
          validade <- liftIO (addUTCTime (7 * 86400) <$> getCurrentTime)
          tok <- liftIO (makeJWT (Sessao i) jwt (Just validade))
          case tok of
            Right t -> pure (Token (TE.decodeUtf8 (BL.toStrict t)))
            Left _ -> erro err500 "Falha ao gerar o token"
    _ -> erro err401 "Email ou senha invalidos"

-- ---------------------------------------------------------------
-- Fase 2: perfil
-- ---------------------------------------------------------------

colUsuario :: Query
colUsuario = "SELECT id, nome, email, instituicao, curso, semestre, bio FROM usuarios "

verPerfil :: Banco -> Int64 -> Handler Usuario
verPerfil banco uid =
  comBanco banco (\c -> query c (colUsuario <> "WHERE id = ?") (Only uid)) >>= primeiro

editarPerfil :: Banco -> Int64 -> PerfilIn -> Handler Usuario
editarPerfil banco uid p = do
  validar
    [ (T.null (T.strip (perfilNome p)), "Nome obrigatorio")
    , (perfilSemestre p < 0 || perfilSemestre p > 20, "Semestre invalido")
    , (T.length (perfilBio p) > 500, "Bio muito longa (maximo 500 caracteres)")
    ]
  comBanco banco $ \c ->
    execute
      c
      "UPDATE usuarios SET nome = ?, instituicao = ?, curso = ?, semestre = ?, bio = ? WHERE id = ?"
      (perfilNome p, perfilInstituicao p, perfilCurso p, perfilSemestre p, perfilBio p, uid)
  verPerfil banco uid

-- ---------------------------------------------------------------
-- Fase 2: grupos
-- ---------------------------------------------------------------

colGrupo :: Query
colGrupo =
  "SELECT g.id, g.titulo, g.descricao, g.instituicao, g.modalidade, g.tags, \
  \g.link_externo, g.entrada, g.dono_id, \
  \(SELECT COUNT(*) FROM membros m WHERE m.grupo_id = g.id AND m.status = 'ativo') \
  \FROM grupos g "

semLink :: Grupo -> Grupo
semLink g = g {grupoLink = ""}

validarGrupo :: GrupoIn -> Handler ()
validarGrupo g =
  validar
    [ (T.null (T.strip (giTitulo g)), "Titulo obrigatorio")
    , (giModalidade g `notElem` ["online", "presencial", "hibrido"], "Modalidade invalida")
    , (giEntrada g `notElem` ["aberto", "fechado"], "Entrada invalida")
    , (not (T.null (giLink g)) && not ("http" `T.isPrefixOf` giLink g), "O link deve comecar com http")
    ]

listarGrupos
  :: Banco -> Int64
  -> Maybe Text -> Maybe Text -> Maybe Text -> Maybe Text -> Maybe Int -> Maybe Int
  -> Handler [Grupo]
listarGrupos banco _ busca tag inst modal pagina limite = do
  gs <- comBanco banco $ \c ->
    queryNamed
      c
      ( colGrupo
          <> "WHERE (:busca IS NULL OR g.titulo LIKE :busca OR g.descricao LIKE :busca) \
             \AND (:tag IS NULL OR (',' || g.tags || ',') LIKE '%,' || :tag || ',%') \
             \AND (:inst IS NULL OR g.instituicao = :inst) \
             \AND (:modal IS NULL OR g.modalidade = :modal) \
             \ORDER BY g.id DESC LIMIT :lim OFFSET :off"
      )
      [ ":busca" := padrao
      , ":tag" := fmap (T.toLower . T.strip) tag
      , ":inst" := inst
      , ":modal" := modal
      , ":lim" := lim
      , ":off" := (pag - 1) * lim
      ]
  pure (map semLink gs)
  where
    padrao = fmap (\b -> "%" <> b <> "%") busca
    lim = max 1 (min 50 (fromMaybe 10 limite))
    pag = max 1 (fromMaybe 1 pagina)

-- | O link externo (WhatsApp, Discord...) só aparece para membros ativos.
verGrupo :: Banco -> Int64 -> Int64 -> Handler Grupo
verGrupo banco uid gid = do
  g <- comBanco banco (\c -> query c (colGrupo <> "WHERE g.id = ?") (Only gid)) >>= primeiro
  p <- comBanco banco $ \c -> papelDe c gid uid
  let ativo = fmap snd p == Just "ativo"
  pure (if ativo then g else semLink g)

criarGrupo :: Banco -> Int64 -> GrupoIn -> Handler Grupo
criarGrupo banco uid g = do
  validarGrupo g
  gid <- comBanco banco $ \c -> do
    execute
      c
      "INSERT INTO grupos (titulo, descricao, instituicao, modalidade, tags, link_externo, entrada, dono_id) \
      \VALUES (?,?,?,?,?,?,?,?)"
      ( T.strip (giTitulo g)
      , giDescricao g
      , giInstituicao g
      , giModalidade g
      , normalizarTags (giTags g)
      , giLink g
      , giEntrada g
      , uid
      )
    novo <- lastInsertRowId c
    execute
      c
      "INSERT INTO membros (grupo_id, usuario_id, papel, status) VALUES (?,?,'dono','ativo')"
      (novo, uid)
    pure novo
  verGrupo banco uid gid

atualizarGrupo :: Banco -> Int64 -> Int64 -> GrupoIn -> Handler Grupo
atualizarGrupo banco uid gid g = do
  exigirPapel ["dono", "moderador"] banco gid uid
  validarGrupo g
  comBanco banco $ \c ->
    execute
      c
      "UPDATE grupos SET titulo = ?, descricao = ?, instituicao = ?, modalidade = ?, \
      \tags = ?, link_externo = ?, entrada = ? WHERE id = ?"
      ( T.strip (giTitulo g)
      , giDescricao g
      , giInstituicao g
      , giModalidade g
      , normalizarTags (giTags g)
      , giLink g
      , giEntrada g
      , gid
      )
  verGrupo banco uid gid

excluirGrupo :: Banco -> Int64 -> Int64 -> Handler Status
excluirGrupo banco uid gid = do
  exigirPapel ["dono"] banco gid uid
  comBanco banco $ \c -> execute c "DELETE FROM grupos WHERE id = ?" (Only gid)
  pure (Status "ok")

-- ---------------------------------------------------------------
-- Fase 3: membros
-- ---------------------------------------------------------------

entrarGrupo :: Banco -> Int64 -> Int64 -> Handler Status
entrarGrupo banco uid gid = do
  r <- comBanco banco $ \c ->
    query c "SELECT entrada FROM grupos WHERE id = ?" (Only gid) :: IO [Only Text]
  case r of
    [Only entrada] -> do
      atual <- comBanco banco $ \c -> papelDe c gid uid
      case atual of
        Just _ -> erro err409 "Voce ja participa deste grupo ou ja solicitou entrada"
        Nothing -> do
          let st = if entrada == "aberto" then "ativo" else "pendente" :: Text
          comBanco banco $ \c ->
            execute
              c
              "INSERT INTO membros (grupo_id, usuario_id, papel, status) VALUES (?,?,'membro',?)"
              (gid, uid, st)
          pure (Status st)
    _ -> naoEncontrado

listarMembros :: Banco -> Int64 -> Int64 -> Handler [Membro]
listarMembros banco uid gid = do
  _ <- exigirAtivo banco gid uid
  comBanco banco $ \c ->
    query
      c
      "SELECT u.id, u.nome, m.papel, m.status FROM membros m \
      \JOIN usuarios u ON u.id = m.usuario_id \
      \WHERE m.grupo_id = ? ORDER BY m.status, u.nome"
      (Only gid)

-- | Gestores aprovam solicitações; só o dono muda papéis.
atualizarMembro :: Banco -> Int64 -> Int64 -> Int64 -> MembroIn -> Handler Status
atualizarMembro banco uid gid alvo (MembroIn papel status) = do
  meu <- exigirAtivo banco gid uid
  unless (meu `elem` ["dono", "moderador"]) $ erro err403 "Sem permissao"
  validar
    [ (papel `notElem` ["moderador", "membro"], "Papel invalido")
    , (status /= "ativo", "Status invalido")
    ]
  atual <- comBanco banco $ \c -> papelDe c gid alvo
  case atual of
    Nothing -> naoEncontrado
    Just (papelAtual, _) -> do
      when (papelAtual == "dono") $ erro err400 "Nao e possivel alterar o dono"
      when (papel /= papelAtual && meu /= "dono") $ erro err403 "Apenas o dono altera papeis"
      comBanco banco $ \c ->
        execute
          c
          "UPDATE membros SET papel = ?, status = ? WHERE grupo_id = ? AND usuario_id = ?"
          (papel, status, gid, alvo)
      pure (Status "ok")

-- | Serve para sair do grupo (alvo = eu) ou remover alguém.
removerMembro :: Banco -> Int64 -> Int64 -> Int64 -> Handler Status
removerMembro banco uid gid alvo = do
  atual <- comBanco banco $ \c -> papelDe c gid alvo
  case atual of
    Nothing -> naoEncontrado
    Just (papelAlvo, _) -> do
      when (papelAlvo == "dono") $ erro err400 "O dono nao pode sair; exclua o grupo"
      unless (uid == alvo) $ do
        meu <- exigirAtivo banco gid uid
        let permitido = meu == "dono" || (meu == "moderador" && papelAlvo == "membro")
        unless permitido $ erro err403 "Sem permissao"
      comBanco banco $ \c ->
        execute c "DELETE FROM membros WHERE grupo_id = ? AND usuario_id = ?" (gid, alvo)
      pure (Status "ok")

-- ---------------------------------------------------------------
-- Fase 4: encontros
-- ---------------------------------------------------------------

colEncontro :: Query
colEncontro =
  "SELECT e.id, e.grupo_id, e.titulo, e.data_hora, e.local_ou_link, e.vagas, \
  \(SELECT COUNT(*) FROM presencas p WHERE p.encontro_id = e.id) \
  \FROM encontros e "

listarEncontros :: Banco -> Int64 -> Int64 -> Handler [Encontro]
listarEncontros banco uid gid = do
  _ <- exigirAtivo banco gid uid
  comBanco banco $ \c ->
    query c (colEncontro <> "WHERE e.grupo_id = ? ORDER BY e.data_hora") (Only gid)

criarEncontro :: Banco -> Int64 -> Int64 -> EncontroIn -> Handler Encontro
criarEncontro banco uid gid e = do
  exigirPapel ["dono", "moderador"] banco gid uid
  validar
    [ (T.null (T.strip (eiTitulo e)), "Titulo obrigatorio")
    , (T.length (eiDataHora e) < 16, "Data e hora invalidas")
    , (eiVagas e < 0, "Vagas invalidas")
    ]
  eid <- comBanco banco $ \c -> do
    execute
      c
      "INSERT INTO encontros (grupo_id, titulo, data_hora, local_ou_link, vagas) VALUES (?,?,?,?,?)"
      (gid, T.strip (eiTitulo e), eiDataHora e, eiLocal e, eiVagas e)
    lastInsertRowId c
  comBanco banco (\c -> query c (colEncontro <> "WHERE e.id = ?") (Only eid)) >>= primeiro

confirmarPresenca :: Banco -> Int64 -> Int64 -> Handler Status
confirmarPresenca banco uid eid = do
  r <- comBanco banco $ \c ->
    query
      c
      "SELECT grupo_id, vagas, (SELECT COUNT(*) FROM presencas WHERE encontro_id = ?) \
      \FROM encontros WHERE id = ?"
      (eid, eid) :: IO [(Int64, Int, Int)]
  case r of
    [(gid, vagas, confirmados)] -> do
      _ <- exigirAtivo banco gid uid
      when (vagas > 0 && confirmados >= vagas) $ erro err409 "Encontro lotado"
      comBanco banco $ \c ->
        execute c "INSERT OR IGNORE INTO presencas (encontro_id, usuario_id) VALUES (?,?)" (eid, uid)
      pure (Status "ok")
    _ -> naoEncontrado

cancelarPresenca :: Banco -> Int64 -> Int64 -> Handler Status
cancelarPresenca banco uid eid = do
  comBanco banco $ \c ->
    execute c "DELETE FROM presencas WHERE encontro_id = ? AND usuario_id = ?" (eid, uid)
  pure (Status "ok")

-- ---------------------------------------------------------------
-- Fase 5: materiais e avisos
-- ---------------------------------------------------------------

colMaterial :: Query
colMaterial =
  "SELECT m.id, m.titulo, m.url, u.nome, m.criado_em FROM materiais m \
  \JOIN usuarios u ON u.id = m.autor_id "

listarMateriais :: Banco -> Int64 -> Int64 -> Handler [Material]
listarMateriais banco uid gid = do
  _ <- exigirAtivo banco gid uid
  comBanco banco $ \c ->
    query c (colMaterial <> "WHERE m.grupo_id = ? ORDER BY m.id DESC") (Only gid)

criarMaterial :: Banco -> Int64 -> Int64 -> MaterialIn -> Handler Material
criarMaterial banco uid gid m = do
  _ <- exigirAtivo banco gid uid
  validar
    [ (T.null (T.strip (mtTitulo m)), "Titulo obrigatorio")
    , (not ("http" `T.isPrefixOf` mtUrl m), "A URL deve comecar com http")
    ]
  mid <- comBanco banco $ \c -> do
    execute
      c
      "INSERT INTO materiais (grupo_id, autor_id, titulo, url) VALUES (?,?,?,?)"
      (gid, uid, T.strip (mtTitulo m), mtUrl m)
    lastInsertRowId c
  comBanco banco (\c -> query c (colMaterial <> "WHERE m.id = ?") (Only mid)) >>= primeiro

colAviso :: Query
colAviso =
  "SELECT a.id, a.texto, u.nome, a.criado_em FROM avisos a \
  \JOIN usuarios u ON u.id = a.autor_id "

listarAvisos :: Banco -> Int64 -> Int64 -> Handler [Aviso]
listarAvisos banco uid gid = do
  _ <- exigirAtivo banco gid uid
  comBanco banco $ \c ->
    query c (colAviso <> "WHERE a.grupo_id = ? ORDER BY a.id DESC") (Only gid)

-- | Só dono e moderadores publicam avisos.
criarAviso :: Banco -> Int64 -> Int64 -> AvisoIn -> Handler Aviso
criarAviso banco uid gid (AvisoIn texto) = do
  exigirPapel ["dono", "moderador"] banco gid uid
  validar [(T.null (T.strip texto), "Texto obrigatorio")]
  aid <- comBanco banco $ \c -> do
    execute
      c
      "INSERT INTO avisos (grupo_id, autor_id, texto) VALUES (?,?,?)"
      (gid, uid, T.strip texto)
    lastInsertRowId c
  comBanco banco (\c -> query c (colAviso <> "WHERE a.id = ?") (Only aid)) >>= primeiro