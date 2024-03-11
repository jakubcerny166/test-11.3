STORED XSS
-funkce "def _SanitizeTag(t):" v souboru "sanitize.py" má seznam povolených a zakázaných hodnot.
->potenciální útok by mohl být tento: "<a onmouseover="alert(1)" href="#">read this!</a>", proto je nutné do "disallowed_attributes" přidat toto omezení 'onmouseover'
--> ale v tomto připadě to nijak nepomůže jelikož kontrola disallowed attributes je case sensitive, tzn. ONMOUSEOVER by už zase fungovalo
poznámky: kód neověřuje správnost vstupního html; používá blacklist atribut, což není nejlepší přístup(lze použít uppercase a blacklist se dá obejít); chybí zde další 
filtr hodnot atributů, to může vyeskalovat v útoky pomocí URI(href, src) vložení JavaScriptu 
- potenciální fix: instalace sanitizeru "sanitize-html" a úprava kódu
-> do souboru se importuje "import sanitizeHtml from 'sanitize-html';" a následně se používají tyto knihovny pro bezpečnost
REFLECTED XSS
aby se předešlo tomuto problému je třeba se podívat na kód. Jelikož reflected xss se vkláda do url tak je třeba so ohlídat soubory pracující s url.
Ktomu je soubor "error.gtl" který zobrazuje chybové zprávy, jenže tyto zprávy nejsou v templatu escapovány. Proto je 
třeba upravit "<div class="message">{{_message}}</div>" na tuto podobu -> "<div class="message">{{_message:text}}</div>"
-> díky tomuto lze nyni escapovat uživatelský vstup
XSRF 
- v kódu je upravená verze metody _DoDeletesnippet v souboru "gruyere.py", která umělě využíva verifikaci crsf tokenu. Tuto funkci je třeba implementovat a následně s kódem zprovoznit, ale je to
potenciální ochrana před XSRF, tedy aspoň v tomto případě
- Provedené změny:
Ověření vstupu: Přidána základní kontrola, abychom zajistili, že parametr indexu je řetězec. Možná bude třeba další ověření (např. zkontrolovat, zda se jedná o platné celé číslo v rozsahu)
Ověření tokenu CSRF: Tato metoda nyní zahrnuje volání hypotetické funkce _VerifyCSRFToken. Tato funkce by měla zkontrolovat přítomnost platného tokenu CSRF přidruženého 
k relaci uživatele a akci odstranění.