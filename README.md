OwnCloud-Installation der MLU
=============================


# Verzeichnisstruktur
 - `/` -> Wurzelverzeichnis
    - `mlu-theme/` -> Design-Anpassungen an die MLU -> [Details](mlu-theme/readme.md)
    - `oc-data/` -> Owncloud-Datenverzeichnis außerhalb des web-root
    - `user-tenplate/` -> Skelett für neue Nutzer
 
    - `cloud.uni-halle.de-apache/` -> Symlink zur owncloud-Installation; DocumentRoot für Web-Server
        - `config.php` -> Symlink zur Konfiguration--Datei in der Wurzel
    - `owncloud-{version}` -> Aktuell im Einsatz befindliche Version
 
    - `config.php` -> OwnCloud-Konfiguration; nicht im Repo
    
    - `cloud.uni-halle.de.conf` -> Vhost-Konfigurations-Datei für Apache 2.4 
 
# Aktualisierung der Installation
 1. `oc-data/` und Datenbank sichern
 2. neue Version von Owncloud herunterladen und entpacken
 3. apache stoppen
 4. ~~Symlink `cloud.uni-halle.de-apache` auf neue Version setzen~~
 5. `upgrade-owncloud.sh` ausführen; Dies erzeugt die Symlinks für theme und config.php in der Produktionsumgebung
 6. Update durchführen: `sudo -u www-data php occ upgrade`
 7. Apache wieder starten


