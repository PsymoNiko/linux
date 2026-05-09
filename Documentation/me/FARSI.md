
# راهنمای محافظت از سرورهای ایزوله  
### پوشش CVE‑2026‑31431 (Copy Fail) و فراتر از آن

این سند یک چک‌لیست لایه‌لایه و عملی برای ایمن‌سازی سرورهای ایزوله (چه فیزیکی، چه ماشین مجازی یا نمونه‌های ابری) در اختیارتان می‌گذارد. تمرکز اصلی روی داکر، GPU، پایتون و سخت‌سازی سیستم‌عامل است و راهنمای اولیه‌ی رفع CVE‑2026‑31431 را به یک استراتژی دفاع عمیق تبدیل می‌کند.

---

## ۱. تشخیص آسیب‌پذیری و بررسی وضعیت

پیش از هر اقدامی، دستورهای زیر را اجرا کنید تا ببینید سرورتان در برابر **Copy Fail** و سایر ضعف‌هایی که ممکن است به فرار از کانتینر یا افزایش سطح دسترسی محلی منجر شوند چقدر مقاوم است.

| هدف | دستور / بررسی | نکته |
|-------|-----------------|-------|
| پیکربندی هسته (algif_aead) | `grep -E '^CONFIG_CRYPTO_USER_API_AEAD=' /boot/config-$(uname -r)` | `=m` یعنی ماژول است (می‌توان آن را در لیست سیاه گذاشت یا حذف کرد). `=y` یعنی درونی هسته است (غیرفعال‌سازی سخت‌تر). |
| آیا ماژول بارگذاری شده؟ | `lsmod \| grep algif_aead` | خروجی خالی یعنی ماژول بارگذاری نشده (خوب). اگر چیزی نشان داد، آسیب‌پذیرید. |
| نسخه هسته در حال اجرا | `uname -r` | با نسخه‌های اصلاح‌شده مقایسه کنید: 6.19.12+, 6.18.22+, 6.12.85+, 6.6.98+, 6.1.170+, 7.0+. |
| نسخه موتور داکر | `docker version` | باید **≥ 29.4.2** باشد (پروفایل seccomp پیش‌فرض اصلاح‌شده). |
| NVIDIA Container Toolkit | `nvidia-ctk --version` | باید **> 1.17.3** (رفع‌شده در 1.17.8+) به دلیل CVE-2025-23359. |
| دسترسی پایتون به AF_ALG | `python3 -c "import socket; s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)"` 2>/dev/null | اگر سوکت با موفقیت ساخته شود، سیستم آسیب‌پذیر است. |

---

## ۲. سخت‌سازی سیستم‌عامل میزبان

سیستم‌عامل پایه‌ی اعتماد است. اگر میزبان لو برود، همه‌ی کانتینرها، بارهای کاری GPU و محیط‌های پایتون در اختیار مهاجم قرار می‌گیرند.

### ۲.۱ CVE‑2026‑31431 – راه‌حل دائمی

هسته را به یک نسخه‌ی اصلاح‌شده ارتقا دهید.

```bash
# Debian / Ubuntu
sudo apt update && sudo apt upgrade

# RHEL / AlmaLinux / Rocky / Fedora
sudo dnf update kernel

# Amazon Linux 2 / 2023
sudo yum update kernel

# SUSE / openSUSE
sudo zypper patch

# Arch Linux
sudo pacman -Syu
```

⚠️ حتماً سیستم را راه‌اندازی مجدد کنید تا هسته جدید بارگذاری شود.

۲.۲ CVE‑2026‑31431 – غیرفعال‌سازی ماژول (اگر نمی‌توانید هسته را به‌روز کنید)

```bash
# جلوگیری از بارگذاری algif_aead هنگام بوت
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif.conf

# خارج کردن ماژول از حافظه (فقط اگر به‌صورت ماژول کامپایل شده باشد)
sudo rmmod algif_aead 2>/dev/null

# به‌روزرسانی initramfs تا تنظیمات دائمی شوند
sudo update-initramfs -u
```

اگر هسته‌تان CONFIG_CRYPTO_USER_API_AEAD=y (توکار) را دارد، گزینه‌ی initcall_blacklist=algif_aead_init را به خط فرمان هسته در /etc/default/grub اضافه کنید.

۲.۳ سخت‌سازی عمومی هسته

این خطوط را به /etc/sysctl.conf (یا یک فایل در /etc/sysctl.d/) اضافه کنید و با sudo sysctl -p اعمال نمایید:

```ini
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.randomize_va_space = 2
```

۲.۴ سخت‌سازی SSH

فایل /etc/ssh/sshd_config را ویرایش کنید:

```ini
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
```

سپس سرویس را بازنشانی کنید: sudo systemctl restart sshd.

۲.۵ کنترل دسترسی اجباری (MAC)

· SELinux (در RHEL، Fedora و مشابه):
  ```bash
  sudo setenforce 1
  # برای دائمی شدن: در /etc/selinux/config مقدار SELINUX=enforcing را تنظیم کنید.
  ```
· AppArmor (در Ubuntu، Debian):
  ```bash
  sudo aa-status
  # مطمئن شوید پروفایل‌ها بارگذاری و در حالت enforce هستند.
  ```

۲.۶ فایروال میزبان

سیاست پیش‌فرض ورودی را رد کنید و فقط سرویس‌های ضروری را مجاز کنید.

مثال با UFW:

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw enable
```

برای iptables/nftables هم زنجیره‌ی INPUT باید به DROP ختم شود.

---

۳. امنیت داکر و کانتینرها

Copy Fail می‌تواند برای فرار از کانتینر استفاده شود. بنابراین در داخل داکر به یک استراتژی چندلایه نیاز داریم.

۳.۱ به‌روزرسانی موتور داکر

داکر نسخه ۲۹.۴.۲ یا بالاتر یک پروفایل seccomp پیش‌فرض دارد که خانواده‌ی سوکت AF_ALG (مقدار 38) را رد می‌کند. بدون این به‌روزرسانی، حتی اگر algif_aead روی میزبان حذف شده باشد، یک کانتینر با پروفایل ضعیف می‌تواند آسیب‌پذیر بماند.

```bash
# بررسی نسخه
docker version

# به‌روزرسانی (مثال برای Debian/Ubuntu)
sudo apt update && sudo apt install docker-ce docker-ce-cli containerd.io
```

۳.۲ پروفایل seccomp سفارشی برای داکر قدیمی‌تر

اگر نمی‌توانید داکر را به‌روز کنید، یک پروفایل JSON سفارشی بسازید که صراحتاً socket با family=38 را رد کند.

پروفایل حداقلی (deny-af_alg.json):

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "args": [
        {
          "index": 0,
          "value": 38,
          "op": "SCMP_CMP_EQ"
        }
      ]
    }
  ]
}
```

موقع اجرای کانتینر از این پروفایل استفاده کنید:
docker run --security-opt seccomp=/path/to/deny-af_alg.json ...

۳.۳ داکر بدون ریشه (Rootless)

کل سرویس داکر را در حالت rootless اجرا کنید. این کار یک لایه‌ی ایزوله اضافی با فضای نام کاربری ایجاد می‌کند و ریشه‌ی میزبان را از دسترس حتی یک کانتینر فراری دور نگه می‌دارد.

```bash
# راه‌اندازی یک‌باره
dockerd-rootless-setuptool.sh install
```

۳.۴ حذف قابلیت‌ها و مجوزهای اضافی

· هرگز از --privileged استفاده نکنید.
· همه‌ی قابلیت‌ها را حذف کنید و فقط آنهایی را که واقعاً نیاز دارید برگردانید:

```bash
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ...
```

· گزینه‌ی --security-opt=no-new-privileges را هم اضافه کنید تا برنامه‌های setuid نتوانند امتیاز جدیدی کسب کنند.

۳.۵ سیستم‌فایل ریشه فقط خواندنی

```bash
docker run --read-only ...
```

دایرکتوری‌های نیازمند نوشتن (مثل /tmp, /var/run) را به‌صورت tmpfs یا volume صریحاً سوار کنید.

۳.۶ محدودیت منابع

برای جلوگیری از حملات منع‌ سرویس از داخل کانتینر، همیشه محدودیت حافظه و CPU تعیین کنید:

```bash
docker run --memory="512m" --cpus="1.0" ...
```

۳.۷ امنیت ایمیج‌ها

· از ایمیج‌های پایه‌ی حداقلی (distroless، Alpine با وابستگی‌های دقیق) استفاده کنید.
· پیش از استقرار، ایمیج‌ها را با docker scan، Trivy یا Grype اسکن کنید.
· به‌جای برچسب (tag) از هضم (digest) ایمیج استفاده کنید: image@sha256:....

۳.۸ ابزار Docker Bench Security

ارزیابی استاندارد CIS Docker Benchmark را مرتباً اجرا کنید:

```bash
docker run --rm --net host --pid host --userns host \
  --cap-add audit_control \
  -v /var/lib/docker:/var/lib/docker \
  -v /etc/docker:/etc/docker \
  docker/docker-bench-security
```

---

۴. امنیت GPU و کانتینرهای NVIDIA

کانتینرهای مبتنی بر GPU معمولاً به دسترسی‌های ویژه به درایور NVIDIA نیاز دارند. این سطح حمله‌ی وسیع باید به شدت محدود شود.

۴.۱ به‌روزرسانی NVIDIA Container Toolkit

به نسخه‌ی v1.17.8+ (یا GPU Operator v25.3.1+) ارتقا دهید تا CVE‑2025‑23359 که اجازه‌ی سوار کردن دایرکتوری‌های میزبان را می‌داد برطرف شود.

```bash
# بررسی نسخه
nvidia-ctk --version

# به‌روزرسانی (مثال برای Debian/Ubuntu)
sudo apt update && sudo apt install nvidia-container-toolkit
```

۴.۲ تکنیک‌های ایزوله‌سازی GPU

· MIG (Multi‑Instance GPU) – برای پردازنده‌های A100، A30، H100: یک GPU فیزیکی را به برش‌های ایزوله تقسیم کنید. هر کانتینر برش MIG خود را می‌گیرد و ایزوله‌سازی سخت‌افزاری حافظه و پردازش فراهم می‌شود.
· Time‑slicing – برای GPUهای غیر MIG، زمان‌بندی اشتراکی در Kubernetes (پلاگین دستگاه NVIDIA) را فعال کنید تا لایه‌ای از ایزوله‌سازی زمان‌بندی اضافه شود.
· vNode / microVM – از Kata Containers یا ران‌تایم‌های مبتنی بر Firecracker برای بارهای GPU استفاده کنید. این کار به هر کانتینر یک ماشین مجازی سبک اختصاص می‌دهد و حملات هسته‌ای را بی‌اثر می‌کند.

۴.۳ پرهیز از ایمیج‌های غیرقابل اعتماد GPU

زنجیره‌ی حمله‌ی NVIDIAScape با یک ایمیج کانتینر مخرب شروع شد. همیشه:

· فقط از مخازن معتبر استفاده کنید.
· ایمیج‌ها را برای آسیب‌پذیری‌ها اسکن کنید.
· از ایمیج‌هایی که مسیرهای حساس میزبان (مثل /var/run/docker.sock یا /proc) را سوار می‌کنند دوری کنید.

۴.۴ محدود کردن دسترسی به دستگاه‌ها

برای اجرای کانتینرهای GPU، فقط فایل‌های دستگاهی و کتابخانه‌های ضروری را در معرض قرار دهید. پرچم --gpus در NVIDIA Container Toolkit امن‌تر از سوار کردن دستی /dev/nvidia* است چون از مجموعه‌ی کنترل‌شده‌ای از گره‌های دستگاه استفاده می‌کند.

---

۵. امنیت محیط پایتون

پایتون یکی از بردارهای رایج برای حملاتی مثل Copy Fail است. محیط اجرا و سندباکس‌هایش را ایمن کنید.

۵.۱ مسدودکننده AF_ALG در زمان اجرا

کد تشخیص اولیه را می‌توان به یک بررسی پیش از اجرا تبدیل کرد که اگر AF_ALG در دسترس باشد، اجرا را متوقف کند:

```python
import socket, sys
try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.close()
    print("AF_ALG در دسترس است – سیستم آسیب‌پذیر است. متوقف می‌شوم.", file=sys.stderr)
    sys.exit(1)
except (OSError, PermissionError):
    pass   # خوب است، ساخت سوکت شکست خورد
```

۵.۲ سندباکس RestrictedPython / AST

اگر کد نامطمئنی اجرا می‌کنید، آن را با RestrictedPython تغییر دهید و AST را اعتبارسنجی کنید. این کار ساختارهای خطرناک (__import__، exec، دسترسی به ویژگی‌های خاص و ...) را حذف می‌کند.

۵.۳ سندباکس مبتنی بر کانتینر

کد نامطمئن پایتون را هرگز مستقیماً روی میزبان اجرا نکنید. از یک کانتینر با پروفایل seccomp سفارشی (بخش ۳.۲) به همراه این موارد استفاده کنید:

· --read-only
· --tmpfs /tmp
· --network none (اگر شبکه نیاز نیست)
· --security-opt=no-new-privileges

۵.۴ سندباکس Bubblewrap (bwrap)

برای یک سندباکس سبک بدون داکر:

```bash
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin \
  --tmpfs /tmp \
  --unshare-net \
  --cap-drop ALL \
  python3 /path/to/script.py
```

۵.۵ امنیت وابستگی‌ها

· با pip-audit یا safety کتابخانه‌های خود را از نظر آسیب‌پذیری اسکن کنید.
· نسخه‌ها را دقیقاً پین کنید و از هش‌ها استفاده کنید (pip install --require-hashes).
· از دریافت کد از بسته‌های تأییدنشده‌ی PyPI خودداری کنید.

---

۶. نکات پیاده‌سازی و بهترین روش‌ها

1. دفاع لایه‌ای اجباری است – ترکیبی از کاهش سطح حمله روی میزبان، seccomp داکر و بررسی‌های سطح برنامه را به کار بگیرید. هیچ لایه‌ای به‌تنهایی کافی نیست.
2. همه چیز را در محیط آزمایشی تست کنید – به‌روزرسانی هسته، پروفایل‌های seccomp و تغییرات NCCL ممکن است برنامه‌ها را بشکنند. پیش از انتقال به تولید، اعتبارسنجی کنید.
3. پایش خودکار راه بیندازید – با ابزارهایی مثل Prometheus + Node Exporter یا یک کرون‌جاب ساده که lsmod را چک می‌کند و در صورت ظاهر شدن algif_aead هشدار می‌دهد.
4. به‌روزرسانی‌ها را سریع انجام دهید – چشم‌انداز هسته لینوکس در ۲۰۲۶ (Copy Fail، Stack Clash، DirtyFrag) چرخه‌ی وصله‌های چندروزه را می‌طلبد، نه چند هفته.
5. پیش‌فرض‌ها را امن بچینید – هنگام ایجاد سرورها یا کانتینرهای جدید، از زیرساخت به‌عنوان کد (Terraform، Ansible) استفاده کنید که این کنترل‌های امنیتی را از همان ابتدا اعمال کند.

---

۷. منابع

· وبلاگ امنیتی مایکروسافت – Copy Fail
· کاتالوگ آسیب‌پذیری‌های بهره‌برداری‌شده CISA
· افشای Theori Xint – ۷۳۲ بایت تا ریشه
· توصیه‌نامه امنیتی NVIDIA Container Toolkit
· CIS Docker Benchmark

---

آخرین به‌روزرسانی: ۲۰ مه ۲۰۲۶

