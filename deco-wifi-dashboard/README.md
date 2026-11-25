# Deco Wi-Fi Dashboard

A small program that runs on your laptop, looks at your **TP-Link Deco** mesh Wi-Fi, and tells you
**what is slowing it down and how to fix it**. It was built and tested for the **Deco BE65
(BE11000, Wi-Fi 7)** 3-pack, and it should also work with other Decos that use the same login.

You open it in your web browser. It gives you a score out of 100, the main thing holding your
Wi-Fi back, and a list of fixes in plain English, with the exact menu to tap in the Deco app.

Want a look first? Run `python3 run.py --demo` (see step 3 below). It shows made-up data with a
big red **DEMO** banner, and it doesn't touch your network.

---

## What it does

- **Reads your Decos.** Which Deco is the main one, how each satellite connects back to it
  (cable or Wi-Fi, and how strong), which devices are on which Deco, your Wi-Fi settings, and how
  your Deco connects to the internet.
- **Measures your laptop's connection.** Wi-Fi band (2.4, 5 or 6 GHz), channel width, signal
  strength, ping, DNS speed and a real internet speed test.
- **Checks for bufferbloat.** That's extra lag when your connection is busy. It's why games lag
  when someone starts a download.
- **Gives you a score and a fix list**, most important first.
- **Room tests.** Test from different rooms and compare them to find dead spots and badly placed
  Decos.

## What it does NOT do

- **It never changes your Deco settings.** It is read-only. You make changes yourself in the Deco
  app. The dashboard tells you where to tap.
- **It can't see inside your walls.** It doesn't know where your Decos are or what's between
  them. It works that out from signal numbers, so room tests help a lot.
- **It only measures the computer it runs on.** It can't test your phone's or console's Wi-Fi
  directly (but it does list them and which Deco they use).
- **It doesn't upload your data anywhere.** See [Privacy](#privacy).

---

## Setup in 5 minutes

You need Python 3.9 or newer (it's free) and the `deco-wifi-dashboard` folder.

**Getting the folder from GitHub:** open the repository on GitHub, switch to the branch that has
the dashboard (the branch menu is near the top left), click the green **Code** button, then
**Download ZIP**. Unzip it, and the `deco-wifi-dashboard` folder is inside.

### Mac

1. **Open Terminal.** Press `Cmd + Space`, type `Terminal`, press Enter.
2. **Check Python.** Type `python3 --version` and press Enter.
   - If it says `Python 3.9` or higher, you're good.
   - If a box pops up asking to install "command line developer tools", click **Install**, wait
     for it to finish, then try again.
   - Or get Python from [python.org/downloads](https://www.python.org/downloads/) (pick the macOS
     installer).
3. **Get the folder.** Download the `deco-wifi-dashboard` folder. If it's a `.zip`, double-click it
   to unzip. Moving it into your Downloads folder keeps things simple.
4. **Go into the folder.** In Terminal type `cd ` (with a space after it), drag the folder from
   Finder into the Terminal window, and press Enter. Use the folder that has `run.py` inside it
   (unzipping sometimes makes a folder inside a folder). If your Mac asks whether Terminal may
   access your Downloads folder, click **OK**.
5. **Start it.** Type `python3 run.py` and press Enter.
6. **Open the page.** Your browser should open by itself. If not, copy the link Terminal shows
   (normally `http://127.0.0.1:8765/`) into your browser.

To stop it, click the Terminal window and press `Ctrl + C`.

### Windows

1. **Install Python.** Go to [python.org/downloads](https://www.python.org/downloads/) and get the
   Windows installer. In the first screen of the installer, **tick "Add python.exe to PATH"**, then
   click Install Now.
2. **Get the folder.** Download the `deco-wifi-dashboard` folder. If it's a `.zip`, right-click it,
   choose **Extract All**, then open the extracted folder. Keep going until you see `run.py`
   (Extract All sometimes makes a folder inside a folder).
3. **Open a command window in the folder.** Click the address bar at the top of File Explorer,
   type `cmd` and press Enter.
4. **Start it.** Type `py run.py` and press Enter. (`python run.py` works too. On Windows the
   command is usually `py` or `python`, not `python3`.)
5. **Open the page.** Your browser should open by itself. If not, go to `http://127.0.0.1:8765/`.
6. If **Windows Firewall** asks about Python, you can press **Cancel**. The dashboard page only
   works on your own computer, so it doesn't need to accept connections from outside.

To stop it, click the command window and press `Ctrl + C`.

### Preview with sample data

```
python3 run.py --demo
```

(On Windows: `py run.py --demo`.) Everything is made up, so you can click around safely.

### Extra options

| Option | What it does |
|---|---|
| `--demo` | Sample data instead of your network. Nothing is sent anywhere. |
| `--port 8800` | Use a different port if 8765 is busy. |
| `--no-browser` | Don't open the browser by itself. |
| `--deco-host 192.168.0.1` | Your main Deco's address, if it isn't `192.168.68.1`. |

---

## Connecting to your Deco

1. In the **Connect to Deco** card, check the address. It's usually `192.168.68.1`.
2. Type the Deco **owner** password. That's the password of the TP-Link ID that set up the Decos
   in the Deco app. **Manager accounts can't log in here.**
3. Press **Connect**. It takes a few seconds.

Good to know:

- **Connecting logs the owner out of the Deco app on their phone.** A Deco only allows one owner
  login at a time. Nothing breaks: just log in on the app again later. Press **Disconnect** when
  you're done (stopping the dashboard with `Ctrl + C` also logs out).
- **Tip: make a Manager account for the phone.** In the Deco app go to **More → Managers** and
  invite a second TP-Link ID (a different email). Use that account in the app on your phone day
  to day, and keep the owner login for this dashboard. Then they won't keep kicking each other
  out.
- **Your password is never saved.** It only lives in your computer's memory while the dashboard
  runs, and it's gone when you disconnect or stop it.

You don't have to connect at all. Without the Deco login, the dashboard still measures your
laptop's Wi-Fi, ping, DNS and speed. You just get fewer tips.

---

## Using it

1. In **Settings**, type the download and upload speed your internet plan promises (it's on your
   bill or your provider's app). Mbps means megabits per second. Without this, the dashboard
   can't tell if you're getting what you pay for.
2. Press **Quick check** (about 20 seconds) or **Run full check** (adds a speed test, about 40
   seconds in total). The speed test uses a few hundred MB of data, and up to about 1 GB on a very
   fast plan, so skip it on a phone hotspot or a capped plan.
3. Read **Fix these first**. Tap a tip to see why it matters, how to fix it, and the numbers
   behind it.
4. After changing something in the Deco app, wait a minute and run the check again to see if it
   helped.

### Room tests

Room tests show you where the Wi-Fi is good and where it's not.

1. Use a laptop on **Wi-Fi**, not plugged in with a cable.
2. Walk to a room and wait about 10 seconds, so the laptop can switch to the nearest Deco.
3. Type the room's name in **Room tests** and press **Test this room**.
4. Keep the laptop still for about 30 seconds. Pause big downloads and 4K streams while it runs.
5. Repeat in 3 or 4 rooms: one near each Deco, the rooms you use most, and the spot you think is
   worst.

How to read the results:

- **Download** compared to your plan. Near a Deco you should get most of your plan.
- **Signal** in dBm. Closer to 0 is stronger:
  - `-55` or better: great
  - `-55` to `-67`: good
  - `-67` to `-75`: okay
  - below `-75`: weak
- **Deco** shows which Deco the laptop was connected to. If you're right next to one Deco but
  connected to another one far away, try turning on Fast Roaming.
- **Deco ping** is the ping to your main Deco. On a good Wi-Fi link it's under about 10 ms.

Patterns to look for:

- **Every room is slow, even next to the main Deco:** the problem is the internet side (your plan,
  your provider, bufferbloat or double NAT), not your Wi-Fi.
- **Rooms near one satellite are slow, rooms near the main Deco are fast:** that satellite's link
  back to the main Deco (the "backhaul") is weak. Move it closer or connect it with a cable.
- **One room is slow and the signal is weak:** that room is a gap. Move the nearest Deco a bit
  closer to it or higher up.

---

## The optimal setup, in short

The dashboard checks these for you and shows the exact Deco app menu for each. Menu names can
change a bit between app versions.

1. **Main Deco in the open:** central, up high, not in a cupboard, behind a TV, or on the floor.
2. **Satellites about halfway** between the main Deco and the area that needs Wi-Fi, with a
   strong link back (about -65 dBm or better).
3. **Ethernet backhaul is best.** If you can run a cable between Decos, do it. The Decos switch to
   the cable by themselves.
4. **Plan over 1 Gbps?** Use the 2.5 Gbps ports and Cat6 cable.
5. **6 GHz on**, and **MLO on** for Wi-Fi 7 devices (Deco app → More → Wi-Fi Settings → MLO
   Network).
6. **One network name** for all bands, not hidden.
7. **Fast Roaming and Beamforming on** (Deco app → More → Advanced).
8. **IoT network** for smart plugs, bulbs and other gadgets (Deco app → More → IoT Network).
9. **No double NAT.** If your provider's box is also a router, put it in bridge mode, or switch the
   Deco to Access Point mode (Deco app → More → Advanced → Operation Mode).
10. **QoS on** if your bufferbloat grade is C or worse (Deco app → More → QoS).
11. **Firmware up to date**, and the same on every Deco (Deco app → More → System → Update Deco).
12. **IPv6 on** if your provider supports it.

---

## Privacy

- **Everything stays on your computer.** The page only opens on this computer (`127.0.0.1`), and
  it needs a secret code that changes every time you start the dashboard.
- **Your Deco password stays in memory only.** It's never written to a file or a log, and it's
  never shown on the page.
- **Wi-Fi passwords** that the Deco sends are removed before anything is shown or exported.
- **What gets saved:** your room tests (`history.json`) and settings like plan speeds and the Deco
  address (`settings.json`), in a folder called `.decodash` in your home folder
  (`~/.decodash` on Mac, `C:\Users\<you>\.decodash` on Windows). Delete that folder to wipe
  everything. Demo mode saves its sample room tests in `demo-history.json` there, so they never
  mix with your real ones.
- **Who it talks to:** your Deco (on your home network), Cloudflare's public speed test
  (`speed.cloudflare.com`), pings to `1.1.1.1` and `8.8.8.8`, and DNS lookups of a few popular
  websites. No accounts, no tracking, no analytics.
- **Export JSON** saves the same data you see under "Raw data", with passwords removed. Have a
  look before you share it, because it does include your device names and IP addresses.

---

## Troubleshooting

**"Couldn't reach your Deco" / can't reach 192.168.68.1**
- Make sure the laptop is on your **home Wi-Fi** (not a phone hotspot), and turn off any **VPN**.
- Check the real address: on an iPhone go to **Settings → Wi-Fi → tap (i) next to your network →
  Router**. On a Mac: **System Settings → Wi-Fi → Details → TCP/IP → Router**. On Windows: type
  `ipconfig` in a command window and look for **Default Gateway**. Type that number in the
  dashboard.
- If your Deco runs in Access Point mode, it has a different address. Find it in the Deco app by
  tapping the main Deco.

**The Deco redirects to https**
Some firmware switches to `https://` with its own certificate. The dashboard handles this by
itself (only for addresses inside your home network). You can also type `https://192.168.68.1`.

**"That password didn't work"**
Use the **owner** password (the TP-Link ID that set up the Decos), not a manager account. After a
few wrong tries the Deco blocks logins for a while, so wait a bit before trying again.

**"Refused the login (HTTP 403)"**
Someone is logged in as owner somewhere else, usually the Deco app on a phone. Close the app
completely, wait a minute, and try again.

**The Deco app on my phone logged me out**
That's normal (see [Connecting to your Deco](#connecting-to-your-deco)). Press Disconnect in the
dashboard and log in on the app again, or use the Manager account tip.

**"Firmware not supported"**
Older Deco firmware uses a different login that this tool can't do. Update the Deco firmware in
the app (More → System → Update Deco) and try again.

**Speed test fails with a certificate error on Mac (`CERTIFICATE_VERIFY_FAILED`)**
The python.org version of Python needs its certificates installed once. Open **Finder →
Applications → Python 3.x** and double-click **Install Certificates.command**. Then try again.

**Windows Firewall pops up**
You can press Cancel. The dashboard still works, because the page only runs on your own computer.

**"Port 8765 is already in use"**
The dashboard may already be running in another window. Close it, or start with a different port:
`python3 run.py --port 8800`.

**The page says "Forbidden"**
You're using an old tab. The secret code changes every time the dashboard starts, so open the link
that `run.py` printed this time.

**"can't open file ... run.py"**
You're in the wrong folder. Go into the folder that has `run.py` in it (see step 4 on Mac or step 3
on Windows) and try again.

**`python3` isn't found on Windows**
Use `py run.py` or `python run.py` instead.

**The network name says "hidden by macOS"**
Newer macOS hides the Wi-Fi name from apps that don't have Location permission. It doesn't change
your results.

**Speeds jump around between tests**
That's normal for Wi-Fi. Run the test 2 or 3 times and pause other downloads and streams.

---

## For the curious

- Python standard library only. If the `cryptography` package happens to be installed, the Deco
  login uses it to go a bit faster.
- Run the tests with `python3 -m unittest discover -s tests -v` from this folder. They use a fake
  Deco and never touch your network.
- `SPEC.md` explains how all the parts fit together.
