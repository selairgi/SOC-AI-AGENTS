# 🔄 Comment Réinitialiser le Rate Limit

## 📌 Contexte

Votre application SOC utilise **Flask-Limiter** pour limiter le nombre de requêtes:
- **500 requêtes par heure** (limite globale)
- **1000 requêtes par jour** (limite globale)
- Limites spécifiques par endpoint (voir détails ci-dessous)

Le stockage des compteurs se fait dans **Redis** (avec fallback en mémoire).

---

## 🚀 Méthodes pour Réinitialiser

### ✅ Méthode 1: Script Rapide (RECOMMANDÉ)

**Le plus simple et le plus rapide!**

```bash
quick-reset-rate-limit.bat
```

**Ce que ça fait:**
- Redémarre le conteneur web
- Les compteurs en mémoire sont effacés automatiquement
- Prend ~5 secondes

---

### ✅ Méthode 2: Script Interactif

**Pour plus de contrôle:**

```bash
reset-rate-limit.bat
```

**Options disponibles:**
1. **Redémarrer le conteneur web** (efface les compteurs en mémoire)
2. **Vider le cache Redis** (efface les compteurs persistants)
3. **Les deux** (nettoyage complet)

---

### ✅ Méthode 3: Script Python

**Pour vider Redis directement:**

```bash
python clear_rate_limits_redis.py
```

**Avantages:**
- Montre exactement combien de clés sont supprimées
- Affiche les clés de rate limit trouvées
- Diagnostics détaillés en cas d'erreur

---

### ✅ Méthode 4: Commandes Manuelles Docker

**Si vous préférez les commandes directes:**

#### Option A: Redémarrer le conteneur web
```bash
docker compose restart web
```

#### Option B: Vider Redis
```bash
# Voir toutes les clés de rate limit
docker compose exec redis redis-cli KEYS "LIMITER*"

# Supprimer toutes les clés de rate limit
docker compose exec redis redis-cli --scan --pattern "LIMITER*" | xargs docker compose exec -T redis redis-cli DEL
```

#### Option C: Vider complètement Redis (⚠️ ATTENTION)
```bash
# Supprime TOUT dans Redis (rate limits, sessions, cache)
docker compose exec redis redis-cli FLUSHALL
```

---

## 📊 Configuration Actuelle des Rate Limits

### Limites Globales
- **500 requêtes par heure** par IP
- **1000 requêtes par jour** par IP

### Limites par Endpoint

| Endpoint | Limite | Description |
|----------|--------|-------------|
| `/api/chat` | 10/minute | Envoi de messages au chatbot |
| `/api/soc/toggle` | 5/minute | Activation/désactivation du SOC |
| `/api/soc/status` | 30/minute | Récupération du statut |
| `/api/security/alerts` | 30/minute | Récupération des alertes |
| `/api/test/scenario` | 5/minute | Tests de scénarios |

*(Source: [web/app.py](web/app.py:124))*

---

## 🔍 Vérifier si vous êtes Rate Limited

### Symptômes

1. **Dans le navigateur:**
   - Page blanche ou erreur HTTP 429
   - Message: "Too Many Requests"
   - Délai avant de pouvoir refaire une requête

2. **Dans les logs Docker:**
   ```bash
   docker compose logs web | findstr "ratelimit"
   ```

   Vous verrez:
   ```
   flask-limiter - INFO - ratelimit 500 per 1 hour (172.18.0.1) exceeded at endpoint: index
   werkzeug - INFO - 127.0.0.1 - - [date] "GET / HTTP/1.1" 429 -
   ```

3. **Avec curl:**
   ```bash
   curl -I http://localhost:5000
   ```

   Réponse:
   ```
   HTTP/1.1 429 TOO MANY REQUESTS
   X-RateLimit-Limit: 500
   X-RateLimit-Remaining: 0
   X-RateLimit-Reset: 1702498800
   ```

---

## ⚡ Workflow Typique

### Scénario: Tests Intensifs

1. **Vous faites beaucoup de requêtes** (ex: tests automatisés)
2. **Vous atteignez la limite** → HTTP 429
3. **Vous réinitialisez:**
   ```bash
   quick-reset-rate-limit.bat
   ```
4. **Vous reprenez vos tests!**

### Scénario: Développement

1. **Vous testez l'application**
2. **Rate limit atteint**
3. **Reset rapide:**
   ```bash
   docker compose restart web
   ```
4. **Continuez à développer**

---

## 🛠️ Modifier les Limites (Permanent)

Si vous voulez **augmenter ou diminuer** les limites de façon permanente:

### Fichier: [web/app.py](web/app.py:124)

```python
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "500 per hour"],  # ← Modifier ici
    storage_uri=os.getenv('REDIS_URL', 'memory://')
)
```

**Exemples:**

```python
# Pour tests intensifs (CTF, pentesting)
default_limits=["10000 per day", "5000 per hour"]

# Pour production (sécurité renforcée)
default_limits=["200 per day", "50 per hour"]

# Pas de limite (⚠️ DANGER - seulement pour dev local)
default_limits=[]
```

**Après modification:**
```bash
docker compose restart web
```

---

## 🎯 Résumé Rapide

| Besoin | Commande |
|--------|----------|
| **Reset rapide** | `quick-reset-rate-limit.bat` |
| **Reset avec options** | `reset-rate-limit.bat` |
| **Reset Redis seulement** | `python clear_rate_limits_redis.py` |
| **Vérifier les logs** | `docker compose logs web \| findstr ratelimit` |
| **Vérifier état web** | `docker compose ps web` |

---

## 📝 Notes Importantes

1. **Les rate limits sont par IP**
   - Si vous testez depuis plusieurs machines, chaque IP a son propre compteur
   - Dans Docker, toutes les requêtes locales viennent de la même IP

2. **Redis vs Memory**
   - Par défaut: Redis (persistant)
   - Si Redis est down: Memory (effacé au redémarrage)
   - Configuration: `REDIS_URL` dans `.env`

3. **En Production**
   - Gardez des limites raisonnables (50-200/heure)
   - Utilisez Redis pour partager les limites entre instances
   - Ajoutez une whitelist pour IPs de confiance

4. **Pour Désactiver Complètement** (⚠️ NE PAS FAIRE EN PROD)
   ```python
   # Dans web/app.py
   default_limits=[]
   ```

---

## 🆘 Troubleshooting

### Problème: Le reset ne marche pas

**Solution:**
```bash
# 1. Vérifier que Redis tourne
docker compose ps redis

# 2. Redémarrer Redis ET web
docker compose restart redis web

# 3. Vérifier les logs
docker compose logs web | findstr "Limiter"
```

### Problème: Toujours bloqué après reset

**Causes possibles:**
1. Le navigateur a mis en cache la réponse 429
   - **Solution:** Vider le cache du navigateur (Ctrl+Shift+Del)
   - Ou utiliser mode navigation privée

2. Il y a plusieurs instances de web
   - **Solution:** `docker compose down && docker compose up -d`

3. Les limites sont trop basses
   - **Solution:** Augmenter dans `web/app.py`

---

## 📚 Fichiers Créés

1. **[quick-reset-rate-limit.bat](quick-reset-rate-limit.bat)** - Reset rapide (1 ligne)
2. **[reset-rate-limit.bat](reset-rate-limit.bat)** - Reset interactif (menu)
3. **[clear_rate_limits_redis.py](clear_rate_limits_redis.py)** - Script Python détaillé
4. **Ce guide** - Documentation complète

---

**Créé le:** 2025-12-13
**Dernière mise à jour:** 2025-12-13

---

## 🔗 Ressources

- [Flask-Limiter Documentation](https://flask-limiter.readthedocs.io/)
- [Redis Commands Reference](https://redis.io/commands/)
- [RATE_LIMIT_FIX.md](RATE_LIMIT_FIX.md) - Historique du fix
