{-# LANGUAGE OverloadedStrings #-}
-- | Web and e-mail addresses in messages, like GitHub's autolinks: at the
-- start of a word, or after an opening bracket, quote or emphasis mark.
module Tox.Android.Links
  ( findLinks
  ) where

import           Control.Applicative ((<|>))
import           Data.Char           (isAlphaNum, isAscii, isSpace)
import           Data.Text           (Text)
import qualified Data.Text           as Text

-- | Link text, and the address it opens.
findLinks :: Text -> [(Text, Text)]
findLinks = go True
  where
    go starts text
      | Text.null text = []
      | starts, Just (candidate, rest) <- web text <|> email text =
          maybe id (:) (link candidate) (go False rest)
      | otherwise = let c = Text.head text in go (opens c) (Text.tail text)
    opens c = isSpace c || c `elem` ("([{<\"'*_~" :: String)

web :: Text -> Maybe (Text, Text)
web text
  | any (`Text.isPrefixOf` Text.toLower text) ["http://", "https://", "www."] =
      Just (Text.break (\c -> isSpace c || c `elem` ("<>\"" :: String)) text)
  | otherwise = Nothing

-- | Name, @, and 2 or more labels.
email :: Text -> Maybe (Text, Text)
email text = do
  let (name, afterName) = Text.span (\c -> word c || c `elem` (".+-" :: String)) text
  rest <- Text.stripPrefix "@" afterName
  let labels = takeWhile (not . Text.null) (Text.splitOn "." (Text.takeWhile (\c -> word c || c `elem` ("-." :: String)) rest))
      domain = Text.intercalate "." labels
  if Text.null name || length labels < 2 then Nothing
    else Just (Text.splitAt (Text.length name + 1 + Text.length domain) text)

link :: Text -> Maybe (Text, Text)
link candidate
  | Nothing <- web candidate =
      if Text.last candidate `elem` ("-_" :: String) then Nothing else Just (candidate, "mailto:" <> candidate)
  | hosted trimmed = Just (trimmed, if scheme then trimmed else "https://" <> trimmed)
  | otherwise = Nothing
  where
    trimmed = trim candidate
    scheme = any (`Text.isPrefixOf` Text.toLower trimmed) ["http://", "https://"]

-- | Drops punctuation at the end, and closing brackets without an opening
-- one.
trim :: Text -> Text
trim l = case Text.unsnoc l of
  Just (rest, c)
    | c `elem` ("?!.,:;*_~'" :: String) -> trim rest
    | Just o <- lookup c [(')', '('), (']', '['), ('}', '{')]
    , Text.count (Text.singleton c) l > Text.count (Text.singleton o) l -> trim rest
  _ -> l

-- | Host has 2 or more labels, the last 2 without underscores.
hosted :: Text -> Bool
hosted l = length labels >= 2 && all (\x -> not (Text.null x) && Text.all host x) labels
  && all (Text.all (/= '_')) (drop (length labels - 2) labels)
  where
    bare = maybe l snd (lookup True [(p `Text.isPrefixOf` Text.toLower l, Text.splitAt (Text.length p) l) | p <- ["https://", "http://"]])
    labels = Text.splitOn "." (Text.takeWhile (`notElem` ("/?#:" :: String)) bare)
    host c = word c || c == '-'

-- | Like regex @\\w@.
word :: Char -> Bool
word c = isAscii c && (isAlphaNum c || c == '_')
