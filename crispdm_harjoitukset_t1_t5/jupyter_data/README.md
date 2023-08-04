## yorkshirewater 
### Lähdedatat sekä Jupyter Notebook -tiedosto

Tämän aineiston perusteella tehdään **Tehtävät 1-5** opintojaksolle *Data-analytiikan ja koneoppimisen käytänteet*.

## Jupyter Notebook -suorittaminen

Aja **Jupyter Notebook** -dokumentteja (`.ipynb`-tiedostot) siirtymällä paikalliseen repositorion kansioon ja käynnistä sieltä konsoli 
(nimellä **Anaconda prompt**) komentotilan kautta komennolla `jupyter notebook`.
Tällöin minkä tahansa yksittäisen Jupyter Notebook -dokumentin sisältöä ja koodia pääsee katsomaan sekä tarvittaessa suoraan muokkaamaan Web-selaimelta. 

**Conda-ympäristöt**, jotka koneellesi on asennettu näkee komennolla:

    conda env list

**Anaconda prompt**-komentotulkista tulee vaihtaa oikea ajoympäristö, johon kaikki tarvittavat paketit on asennettu

    conda activate mlearn_env

Vaihda projektin ensin hakemistostoon (juurihakemistoon), josta **Jupyter Notebook** -dokumentit löytyvät omalta paikalliselta koneeltasi.

    (mlearn_env) >cd %PROJEKTIN_HAKEMISTO%

Täältä hakemistosta voit käynnistää **Jupyter Notebook -palvelimen** (*jupyter notebook*), jonka kautta voi suorittaa `.ipynb`-dokumentteja.


    (mlearn_env) %PROJEKTIN_HAKEMISTO%>jupyter notebook
       ::::
       Or copy and paste one of these URLs:
            http://localhost:8888/?token=...

Oletuksena Jupyter Notebook avautuu selaimeen (oletus: *localhost:8888*) ja muuta ei välttämättä tarvita Jupyter Notebookin peruskäyttöön.
Toki ammattimaiseen data-analytiika & tekoäly - kehitykseen tarvitaan jokin Pythonia-kieltä tukeva IDE-sovelluskehitin (esim. PyCharm, Visual Studio Code, Spyder tms)
