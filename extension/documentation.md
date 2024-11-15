# Generalni pregled

Ta del projekta vključuje informacije o razširitvi v Google Chrome

## Funkcionlanosti

1. Samodejno zaznavanje vnosnih polij
2. Prikaz modula za vnos shrajnenega gesla
3. Prikaz gesel iz drugih domen
4. Generiranje novega gesla
5. Samodejni vnos izbranega uporabniškega imena/e-pošte in gesla

## Zgradba projekta

Delovanje razširitve sloni na 3 glavnih delih:

1. Popup.js in index.html

   1. S temi komponentami skrbimo za obnašanje in izgled komponente razširitve, ki se pojavi ob kliku na njo iz opravilne vrstice v Chroom-u
   2. Ta del aplikacije nima dostopa do DOM spletne strani prikazane v Chroom-u

2. Content skripte

   1. Ker nam popup.js ne omogoča dostopa DOM-a si pomagamo z Content skriptami. Ta deluje za vsak zavihek posebej in je vstavljena v gostiteljsko spletno stran

3. Background skripte
   1. Ozadne skripte za razliko od content skript delujejo na obsegu celotnega brskalnika.

## Delovanje aplikacije

Aplikacija deluje tako, da se ob primeru, da je uporabnik prijavljen, na vsaki novi spletni strani zažene algoritem, ki išče vnosna polja. Če jih najde, se na onsovi pozicije le-teh generira modal (content.js).

## Vzpostavitev okolja

1. V Chroom-u pod upravljaj razširitve omogočimo developer mode
2. Stisnemo na gumb Load unpacked
3. Izberemo mapo extension

## Nasveti za razvijanje

1. Uporabi razširitev Chrome Extension Loader
