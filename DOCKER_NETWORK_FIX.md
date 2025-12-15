# 🌐 Fix Docker Network - Connectivité OpenAI

## ❌ Problème Identifié

Vos conteneurs Docker **n'ont pas accès à Internet** pour atteindre `api.openai.com`:

```bash
$ ping api.openai.com
ping: connect: Network is unreachable

$ curl https://api.openai.com
curl: (7) Failed to connect to api.openai.com port 443
```

---

## 🔍 Diagnostic Complet

### Ce qui fonctionne ✅
- **Votre machine hôte** peut ping api.openai.com (en IPv6)
- **Les conteneurs** peuvent communiquer entre eux (postgres, redis, web)
- **IPv4 local** fonctionne (ping 8.8.8.8 réussit)

### Ce qui ne fonctionne pas ❌
- **Résolution DNS** de `api.openai.com` dans les conteneurs
- **Connectivité externe** vers les API OpenAI
- **IPv6** n'est pas activé dans Docker

### Cause Racine

1. **Docker DNS resolver** (127.0.0.11) ne peut pas résoudre `api.openai.com`
2. **IPv6 désactivé** dans le réseau Docker
3. **Aucun DNS public** configuré (Google DNS, Cloudflare, etc.)

---

## ✅ Solution Appliquée

### Modifications dans `docker-compose.yml`

#### 1. **Activation d'IPv6** sur le réseau

Lignes 163-174:
```yaml
networks:
  soc-network:
    driver: bridge
    enable_ipv6: true
    ipam:
      driver: default
      config:
        - subnet: 172.18.0.0/16
          gateway: 172.18.0.1
        - subnet: 2001:db8:1::/64
          gateway: 2001:db8:1::1
    driver_opts:
      com.docker.network.bridge.name: soc-bridge
```

#### 2. **Configuration DNS publics** pour les services critiques

**Service `web` (lignes 74-77):**
```yaml
    dns:
      - 8.8.8.8      # Google DNS primaire
      - 8.8.4.4      # Google DNS secondaire
      - 1.1.1.1      # Cloudflare DNS
```

**Service `core` (lignes 107-110):**
```yaml
    dns:
      - 8.8.8.8
      - 8.8.4.4
      - 1.1.1.1
```

**Service `ai` (lignes 160-163):**
```yaml
    dns:
      - 8.8.8.8
      - 8.8.4.4
      - 1.1.1.1
```

### Pourquoi ces DNS?

| DNS | Provider | Avantages |
|-----|----------|-----------|
| `8.8.8.8` | Google | Très fiable, rapide, support IPv4/IPv6 |
| `8.8.4.4` | Google | DNS secondaire de Google |
| `1.1.1.1` | Cloudflare | Le plus rapide, focus sur privacy |

---

## 🚀 Application du Fix

### Méthode 1: Script Automatique (Recommandé)

**Le plus simple:**
```bash
fix-network-and-restart.bat
```

**Ce que fait le script:**
1. Arrête tous les conteneurs
2. Supprime l'ancien réseau
3. Rebuild complet sans cache (inclut ca-certificates)
4. Redémarre avec le nouveau réseau IPv6 + DNS
5. Teste la connectivité automatiquement

**Durée:** ~5-10 minutes

---

### Méthode 2: Commandes Manuelles

Si vous préférez le contrôle manuel:

```bash
# 1. Arrêter et supprimer tout
docker compose down

# 2. Supprimer l'ancien réseau
docker network rm socaiagentscursor_soc-network

# 3. Rebuild sans cache (pour inclure ca-certificates)
docker compose build --no-cache

# 4. Redémarrer
docker compose up -d

# 5. Attendre le démarrage
timeout /t 15

# 6. Tester
docker compose exec web curl -I https://api.openai.com
```

---

## 🧪 Tests de Validation

Après le fix, vérifiez que tout fonctionne:

### Test 1: Ping IPv4
```bash
docker compose exec web ping -c 4 8.8.8.8
```
✅ **Attendu:** 0% packet loss

### Test 2: Résolution DNS
```bash
docker compose exec web sh -c "curl -I https://www.google.com"
```
✅ **Attendu:** HTTP/2 200

### Test 3: OpenAI API
```bash
docker compose exec web curl -I https://api.openai.com
```
✅ **Attendu:** HTTP/2 200 (ou 301/302)

### Test 4: Script Complet
```bash
test-openai-docker.bat
```
✅ **Attendu:** Tous les tests passent

### Test 5: Python OpenAI
```bash
docker compose exec web python /app/test_openai_connection.py
```
✅ **Attendu:** "SUCCESS: OpenAI API is working correctly!"

---

## 📊 Vérification de la Configuration

### Voir le réseau actif
```bash
docker network inspect socaiagentscursor_soc-network
```

**Ce que vous devriez voir:**
```json
{
  "EnableIPv6": true,
  "IPAM": {
    "Config": [
      {"Subnet": "172.18.0.0/16"},
      {"Subnet": "2001:db8:1::/64"}  // ← IPv6 activé
    ]
  }
}
```

### Voir les DNS dans un conteneur
```bash
docker compose exec web cat /etc/resolv.conf
```

**Ce que vous devriez voir:**
```
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
```

---

## 🆘 Troubleshooting

### Problème: "Network is unreachable" persiste

**Causes possibles:**
1. Docker Desktop pas redémarré
2. Firewall Windows bloque Docker
3. VPN ou Proxy interfère

**Solutions:**

```bash
# 1. Redémarrer Docker Desktop complètement
# (Clic droit sur l'icône Docker → Quit Docker Desktop)
# Puis relancer Docker Desktop

# 2. Vérifier les réseaux Docker
docker network ls
docker network prune  # Supprimer les réseaux non utilisés

# 3. Recréer complètement
docker compose down -v  # -v supprime aussi les volumes
docker compose up -d
```

### Problème: "Could not resolve host"

**Solution:**
```bash
# Vérifier que les DNS sont bien configurés
docker compose exec web cat /etc/resolv.conf

# Si les DNS ne sont pas là, recréer le conteneur
docker compose up -d --force-recreate web
```

### Problème: Connectivité IPv4 OK mais pas IPv6

**C'est normal!** Si IPv4 fonctionne, OpenAI API marchera. IPv6 est un bonus.

**Vérifier:**
```bash
# Test IPv4 seulement
docker compose exec web curl -4 -I https://api.openai.com

# Test IPv6 seulement (peut échouer)
docker compose exec web curl -6 -I https://api.openai.com
```

### Problème: Certificats SSL invalides

**Solution:**
```bash
# Vérifier que ca-certificates est installé
docker compose exec web ls /etc/ssl/certs/ | grep ca-certificates

# Si absent, rebuild
docker compose build --no-cache web
docker compose up -d web
```

---

## 🎯 Checklist Complète

Avant de considérer que le problème est résolu:

- [ ] `docker compose exec web ping -c 2 8.8.8.8` → 0% loss
- [ ] `docker compose exec web curl -I https://www.google.com` → HTTP/2 200
- [ ] `docker compose exec web curl -I https://api.openai.com` → HTTP/2 200
- [ ] `docker compose exec web cat /etc/resolv.conf` → Contient 8.8.8.8
- [ ] `docker network inspect socaiagentscursor_soc-network` → "EnableIPv6": true
- [ ] `test-openai-docker.bat` → Tous les tests passent
- [ ] `python test_openai_connection.py` → SUCCESS

---

## 📝 Fichiers Modifiés

1. **[docker-compose.yml](docker-compose.yml)**
   - Lignes 74-77: DNS pour service web
   - Lignes 107-110: DNS pour service core
   - Lignes 160-163: DNS pour service ai
   - Lignes 163-174: Configuration réseau avec IPv6

2. **[fix-network-and-restart.bat](fix-network-and-restart.bat)** (créé)
   - Script de fix automatique

3. **Ce guide** (créé)

---

## 🔗 Références

- [Docker Network Documentation](https://docs.docker.com/network/)
- [Docker Compose DNS Configuration](https://docs.docker.com/compose/compose-file/compose-file-v3/#dns)
- [IPv6 in Docker](https://docs.docker.com/config/daemon/ipv6/)
- [OpenAI API Status](https://status.openai.com/)

---

## 📞 Support

Si le problème persiste après avoir suivi ce guide:

1. **Vérifier les logs:**
   ```bash
   docker compose logs web | findstr "error"
   docker compose logs core | findstr "error"
   ```

2. **Vérifier Docker Desktop:**
   - Settings → Resources → Network
   - Settings → Docker Engine (vérifier la config IPv6)

3. **Redémarrer complètement:**
   ```bash
   docker compose down -v
   # Redémarrer Docker Desktop
   docker compose up -d
   ```

---

**Créé le:** 2025-12-13
**Problème:** Conteneurs Docker sans accès Internet à OpenAI API
**Solution:** IPv6 + DNS publics (Google, Cloudflare)
**Status:** ✅ Prêt à tester

---

## 🎉 Après le Fix

Une fois que la connectivité fonctionne, vous pourrez:

✅ Appeler l'API OpenAI depuis les conteneurs
✅ Utiliser GPT-4o-mini dans votre application
✅ Tester tous les scénarios de sécurité
✅ Avoir des réponses AI dans le chatbot

**Prochaine étape:** Exécuter `fix-network-and-restart.bat` 🚀
