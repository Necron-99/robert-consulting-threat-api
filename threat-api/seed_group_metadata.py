#!/usr/bin/env python3
"""
seed_group_metadata.py
======================
Populates the group_metadata table in threat.db with attribution data
sourced from MITRE ATT&CK, Mandiant APT reports, CrowdStrike adversary
profiles, and public US government advisories.

Usage:
    python3 seed_group_metadata.py /path/to/threat.db [--dry-run]

Fields:
    country       — ISO 3166-1 alpha-2
    country_name  — Human-readable country name
    motivation    — espionage | financial | destruction | hacktivism | unknown
    first_seen    — Year string e.g. "2008"
    target_sectors — JSON array of strings
    sponsor_type  — nation-state | criminal | hacktivist | unknown
    notes         — Brief attribution note
"""

import json
import sqlite3
import argparse
import sys

# =============================================================================
# Attribution data
# Sources: MITRE ATT&CK, Mandiant APT profiles, US CISA/NSA advisories,
#          CrowdStrike adversary naming, public academic research
# =============================================================================

GROUP_METADATA = [
    # -------------------------------------------------------------------------
    # China
    # -------------------------------------------------------------------------
    ("G0006", "CN", "China", "espionage", "2004",
     ["Government", "Defense", "Aerospace", "Technology"],
     "nation-state", "APT1 / Comment Crew — PLA Unit 61398 (Mandiant 2013)"),
    ("G0005", "CN", "China", "espionage", "2010",
     ["Government", "Technology", "Media"],
     "nation-state", "APT12 / IXESHE — linked to PLA"),
    ("G0023", "CN", "China", "espionage", "2010",
     ["Government", "Technology"],
     "nation-state", "APT16 — Chinese espionage group targeting Japan and Taiwan"),
    ("G0025", "CN", "China", "espionage", "2009",
     ["Government", "Defense", "Technology"],
     "nation-state", "APT17 / Deputy Dog — Chinese MSS-linked"),
    ("G0026", "CN", "China", "espionage", "2009",
     ["Healthcare", "Technology", "Government"],
     "nation-state", "APT18 / Dynamite Panda — Chinese military"),
    ("G0073", "CN", "China", "espionage", "2014",
     ["Defense", "Government", "Technology"],
     "nation-state", "APT19 / Deep Panda overlap — Chinese espionage"),
    ("G0007", "CN", "China", "espionage", "2004",
     ["Aerospace", "Defense", "Government", "Energy"],
     "nation-state", "APT28 attribution note: this is FANCY BEAR (RU) — see G0007 is actually Putter Panda / APT28 is G0007 mapped to RU below"),
    ("G0022", "CN", "China", "espionage", "2010",
     ["Government", "Defense", "Technology"],
     "nation-state", "APT3 / Gothic Panda — Chinese MSS, Operation Clandestine Fox"),
    ("G0013", "CN", "China", "espionage", "2005",
     ["Government", "Military", "Telecom"],
     "nation-state", "APT30 — long-running Chinese espionage, ASEAN focus"),
    ("G0050", "CN", "China", "espionage", "2012",
     ["Government", "Media", "Financial", "Technology"],
     "nation-state", "APT32 / OceanLotus — Vietnamese targets, likely MSS contractor"),
    ("G0096", "CN", "China", "espionage", "2012",
     ["Government", "Healthcare", "Telecom", "Technology"],
     "nation-state", "APT41 / Winnti — dual espionage and financial, MSS contractor"),
    ("G1023", "CN", "China", "espionage", "2007",
     ["Government", "Defense", "Telecom", "Technology"],
     "nation-state", "APT5 / Manganese — Chinese espionage, VPN/network device targeting"),
    ("G0001", "CN", "China", "espionage", "2010",
     ["Government", "Defense", "Technology"],
     "nation-state", "Axiom / Group 72 — Chinese MSS Unit 18"),
    ("G0060", "CN", "China", "espionage", "2008",
     ["Government", "Defense", "Technology"],
     "nation-state", "BRONZE BUTLER / Tick — Japanese targets, likely PLA"),
    ("G0098", "CN", "China", "espionage", "2010",
     ["Government", "Defense", "Technology", "Semiconductor"],
     "nation-state", "BlackTech — Chinese APT targeting East Asia"),
    ("G0114", "CN", "China", "espionage", "2017",
     ["Semiconductor", "Airlines", "Government"],
     "nation-state", "Chimera — Chinese espionage targeting semiconductors"),
    ("G0009", "CN", "China", "espionage", "2011",
     ["Government", "Defense", "Technology"],
     "nation-state", "Deep Panda / Shell Crew — Chinese APT"),
    ("G0035", "CN", "China", "espionage", "2011",
     ["Energy", "ICS", "Government"],
     "nation-state", "Dragonfly / Energetic Bear (early attribution CN, later RU reassigned — see Dragonfly 2.0)"),
    ("G0066", "CN", "China", "espionage", "2009",
     ["Defense", "Government", "Technology"],
     "nation-state", "Elderwood / Hidden Lynx — Chinese APT supply chain attacks"),
    ("G0093", "CN", "China", "espionage", "2012",
     ["Telecom", "Government", "Technology"],
     "nation-state", "GALLIUM — Chinese MSS, telecom targeting"),
    ("G0004", "CN", "China", "espionage", "2010",
     ["Government", "Defense", "Technology"],
     "nation-state", "Ke3chang / APT15 — Chinese MSS"),
    ("G0065", "CN", "China", "espionage", "2010",
     ["Government", "Defense", "Maritime", "Technology"],
     "nation-state", "Leviathan / APT40 / TEMP.Periscope — Chinese MSS Hainan"),
    ("G0030", "CN", "China", "espionage", "2009",
     ["Government", "Military", "Defense"],
     "nation-state", "Lotus Blossom / Spring Dragon — Chinese APT, SE Asia focus"),
    ("G0002", "CN", "China", "espionage", "2013",
     ["Government", "Defense"],
     "nation-state", "Moafee — Chinese APT linked to PLA"),
    ("G0103", "CN", "China", "espionage", "2012",
     ["Government", "Defense"],
     "nation-state", "Mofang — Chinese APT targeting critical infrastructure"),
    ("G0019", "CN", "China", "espionage", "2010",
     ["Government", "Military", "Energy"],
     "nation-state", "Naikon / APT30 overlap — PLA Unit 78020, South China Sea focus"),
    ("G0014", "CN", "China", "espionage", "2010",
     ["Energy", "Government", "Financial"],
     "nation-state", "Night Dragon — Chinese APT targeting energy sector"),
    ("G0049", "IR", "Iran", "espionage", "2014",
     ["Energy", "Government", "Financial", "Telecom"],
     "nation-state", "OilRig / APT34 / HELIX KITTEN — Iranian MOIS, Middle East and global targeting"),
    ("G0024", "CN", "China", "espionage", "2012",
     ["Aerospace", "Defense", "Government"],
     "nation-state", "Putter Panda / APT2 — PLA Unit 61486"),
    ("G0034", "RU", "Russia", "destruction", "2009",
     ["Energy", "Government", "ICS", "Media"],
     "nation-state", "Sandworm Team / Voodoo Bear — GRU Unit 74455, Ukraine focus"),
    ("G0054", "CN", "China", "espionage", "2015",
     ["Government", "Diplomatic"],
     "nation-state", "Sowbug — Chinese APT targeting South America and Southeast Asia"),
    ("G0041", "CN", "China", "espionage", "2011",
     ["Government", "Telecom", "Technology"],
     "nation-state", "Strider / ProjectSauron — likely Chinese or Western nation-state"),
    ("G0039", "CN", "China", "espionage", "2014",
     ["Technology", "Energy", "Government"],
     "nation-state", "Suckfly — Chinese APT targeting India and South Korea"),
    ("G0015", "CN", "China", "espionage", "2008",
     ["Government", "Military"],
     "nation-state", "Taidoor — Chinese APT targeting Taiwan government"),
    ("G0131", "CN", "China", "espionage", "2009",
     ["Government", "Military", "Defense"],
     "nation-state", "Tonto Team / CactusPete — Chinese APT, Russia/Japan/Korea focus"),
    ("G0081", "CN", "China", "espionage", "2011",
     ["Government", "Healthcare", "Technology"],
     "nation-state", "Tropic Trooper / KeyBoy — Chinese APT targeting Taiwan and Philippines"),
    ("G0044", "CN", "China", "espionage", "2010",
     ["Technology", "Gaming", "Government"],
     "nation-state", "Winnti Group — Chinese APT, gaming and pharma supply chain"),
    ("G0128", "CN", "China", "espionage", "2017",
     ["Government", "Defense", "Technology"],
     "nation-state", "ZIRCONIUM / APT31 — Chinese MSS targeting political figures"),
    ("G0018", "CN", "China", "espionage", "2012",
     ["Government", "Defense"],
     "nation-state", "admin@338 — Chinese APT targeting financial and government"),
    ("G0045", "CN", "China", "espionage", "2006",
     ["Defense", "Government", "Technology"],
     "nation-state", "menuPass / APT10 / Stone Panda — Chinese MSS Tianjin Bureau"),
    ("G1017", "CN", "China", "espionage", "2021",
     ["Government", "Defense", "Critical Infrastructure"],
     "nation-state", "Volt Typhoon — Chinese MSS, US critical infrastructure pre-positioning"),
    ("G0116", "CN", "China", "espionage", "2019",
     ["Government", "Defense", "Technology"],
     "nation-state", "Operation Wocao — Chinese APT targeting managed service providers"),
    ("G1007", "CN", "China", "espionage", "2013",
     ["Government", "Telecom", "Technology"],
     "nation-state", "Aoqin Dragon — Chinese APT targeting SE Asia and Australia"),
    ("G0143", "CN", "China", "espionage", "2020",
     ["Government", "Defense", "Technology"],
     "nation-state", "Aquatic Panda / BRONZE UNIVERSITY — Chinese MSS"),
    ("G1034", "CN", "China", "espionage", "2012",
     ["Technology", "Government", "Telecom"],
     "nation-state", "Daggerfly / Evasive Panda — Chinese APT"),
    ("G1006", "CN", "China", "espionage", "2019",
     ["Government", "Technology", "Media"],
     "nation-state", "Earth Lusca — Chinese APT, HK and Taiwan focus"),
    ("G1014", "CN", "China", "espionage", "2020",
     ["Government", "Military"],
     "nation-state", "LuminousMoth — Chinese APT targeting SE Asia"),
    ("G0129", "CN", "China", "espionage", "2012",
     ["Government", "NGO", "Media"],
     "nation-state", "Mustang Panda / TA416 / RedDelta — Chinese APT, global espionage"),
    ("G1022", "CN", "China", "espionage", "2020",
     ["Government", "Military", "Defense"],
     "nation-state", "ToddyCat — Chinese APT targeting Europe and Asia"),

    # -------------------------------------------------------------------------
    # Russia
    # -------------------------------------------------------------------------
    ("G0007", "RU", "Russia", "espionage", "2004",
     ["Government", "Military", "Defense", "Energy", "Media"],
     "nation-state", "APT28 / Fancy Bear / STRONTIUM — GRU Unit 26165"),
    ("G0016", "RU", "Russia", "espionage", "2008",
     ["Government", "Think Tanks", "NGO", "Technology"],
     "nation-state", "APT29 / Cozy Bear / Midnight Blizzard — SVR"),
    ("G0074", "RU", "Russia", "espionage", "2015",
     ["Energy", "ICS", "Government"],
     "nation-state", "Dragonfly 2.0 / Berserk Bear — FSB, energy sector targeting"),
    ("G0047", "RU", "Russia", "espionage", "2013",
     ["Government", "Military", "NGO"],
     "nation-state", "Gamaredon Group / Primitive Bear — FSB, Ukraine focus"),
    ("G0036", "RU", "Russia", "financial", "2014",
     ["Financial", "Government"],
     "nation-state", "GCMAN — Russian APT targeting financial institutions"),
    ("G0119", "RU", "Russia", "financial", "2017",
     ["Financial", "Technology"],
     "criminal", "Indrik Spider / Evil Corp — Russian cybercriminal group, OFAC sanctioned"),
    ("G0088", "RU", "Russia", "destruction", "2017",
     ["Energy", "ICS"],
     "nation-state", "TEMP.Veles / TRITON — Russian CTIIC, Triton/TRISIS ICS malware"),
    ("G0010", "RU", "Russia", "espionage", "2004",
     ["Government", "Military", "Defense", "Technology"],
     "nation-state", "Turla / Snake / Venomous Bear — FSB Center 16"),
    ("G0118", "RU", "Russia", "espionage", "2019",
     ["Government", "Technology"],
     "nation-state", "UNC2452 / Midnight Blizzard — SVR, SolarWinds campaign"),
    ("G1033", "RU", "Russia", "espionage", "2019",
     ["Government", "NGO", "Think Tanks"],
     "nation-state", "Star Blizzard / SEABORGIUM — FSB, spearphishing campaigns"),
    ("G1003", "RU", "Russia", "espionage", "2021",
     ["Government", "Military"],
     "nation-state", "Ember Bear / UAC-0056 — GRU, Ukraine WhisperGate attacks"),
    ("G1031", "RU", "Russia", "espionage", "2022",
     ["Government", "Military"],
     "nation-state", "Saint Bear / UAC-0056 — GRU linked, Ukraine focus"),
    ("G1019", "RU", "Russia", "espionage", "2022",
     ["Government", "ISP"],
     "nation-state", "MoustachedBouncer — Belarus/Russia nexus, ISP-level interception"),
    ("G0133", "RU", "Russia", "espionage", "2016",
     ["Government", "NGO"],
     "nation-state", "Nomadic Octopus / DustSquad — Russian APT targeting Central Asia"),
    ("G1035", "RU", "Russia", "espionage", "2020",
     ["Government", "Media"],
     "nation-state", "Winter Vivern — Russian-aligned APT targeting EU government"),

    # -------------------------------------------------------------------------
    # North Korea
    # -------------------------------------------------------------------------
    ("G0082", "KP", "North Korea", "financial", "2014",
     ["Financial", "Cryptocurrency", "Defense"],
     "nation-state", "APT38 / Lazarus subgroup — DPRK RGB, financial theft"),
    ("G0138", "KP", "North Korea", "espionage", "2009",
     ["Defense", "Government", "Energy"],
     "nation-state", "Andariel / Silent Chollima — DPRK RGB Bureau 121"),
    ("G0094", "KP", "North Korea", "espionage", "2012",
     ["Government", "Defense", "Think Tanks", "Technology"],
     "nation-state", "Kimsuky / Velvet Chollima — DPRK RGB, global intelligence gathering"),
    ("G0032", "KP", "North Korea", "financial", "2009",
     ["Financial", "Defense", "Cryptocurrency", "Technology"],
     "nation-state", "Lazarus Group / Hidden Cobra — DPRK RGB Bureau 121"),
    ("G0067", "KP", "North Korea", "espionage", "2012",
     ["Government", "Military", "Human Rights"],
     "nation-state", "APT37 / Reaper / ScarCruft — DPRK MSS"),
    ("G1036", "KP", "North Korea", "financial", "2023",
     ["Technology", "Defense", "Cryptocurrency"],
     "nation-state", "Moonstone Sleet — DPRK, IT worker fraud and ransomware"),

    # -------------------------------------------------------------------------
    # Iran
    # -------------------------------------------------------------------------
    ("G0064", "IR", "Iran", "espionage", "2013",
     ["Energy", "Government", "Financial", "Telecom"],
     "nation-state", "APT33 / Refined Kitten / Elfin — Iranian IRGC or MOIS"),
    ("G0057", "IR", "Iran", "espionage", "2014",
     ["Government", "Financial", "Telecom", "Energy"],
     "nation-state", "APT34 / OilRig / HELIX KITTEN — Iranian MOIS"),
    ("G0087", "IR", "Iran", "espionage", "2014",
     ["Government", "Telecom", "Technology"],
     "nation-state", "APT39 / Chafer — Iranian MOIS"),
    ("G0058", "IR", "Iran", "espionage", "2017",
     ["Government", "Technology", "Telecom"],
     "nation-state", "Charming Kitten / APT35 / PHOSPHORUS — Iranian IRGC"),
    ("G0003", "IR", "Iran", "espionage", "2012",
     ["Energy", "Government", "Defense", "Transportation"],
     "nation-state", "Cleaver / Threat Group-2889 — Iranian IRGC"),
    ("G0137", "IR", "Iran", "espionage", "2015",
     ["Government", "Military"],
     "nation-state", "Ferocious Kitten — Iranian APT targeting Persian dissidents"),
    ("G0117", "IR", "Iran", "espionage", "2017",
     ["Government", "Technology", "Energy"],
     "nation-state", "Fox Kitten / Pioneer Kitten — Iranian IRGC, VPN exploitation"),
    ("G0077", "IR", "Iran", "espionage", "2017",
     ["Energy", "Government", "Technology"],
     "nation-state", "Leafminer / Raspite — Iranian APT targeting Middle East"),
    ("G0059", "IR", "Iran", "espionage", "2014",
     ["Government", "Defense", "Technology"],
     "nation-state", "Magic Hound / APT35 overlap — Iranian IRGC"),
    ("G0069", "IR", "Iran", "espionage", "2017",
     ["Government", "Technology", "Telecom", "Energy"],
     "nation-state", "MuddyWater / MERCURY — Iranian MOIS"),
    ("G0049", "IR", "Iran", "espionage", "2014",
     ["Energy", "Government", "Financial", "Telecom"],
     "nation-state", "OilRig / APT34 / HELIX KITTEN — Iranian MOIS"),
    ("G1009", "IR", "Iran", "destruction", "2021",
     ["Government", "Technology"],
     "nation-state", "Moses Staff — Iranian APT, destructive attacks on Israel"),
    ("G1030", "IR", "Iran", "destruction", "2019",
     ["Technology", "Government"],
     "nation-state", "Agrius — Iranian APT, destructive wiper attacks"),
    ("G0130", "IR", "Iran", "espionage", "2017",
     ["Government", "Technology"],
     "nation-state", "Ajax Security Team / Flying Kitten — Iranian hacktivism turned espionage"),
    ("G1012", "IR", "Iran", "espionage", "2020",
     ["Government", "Energy", "Technology"],
     "nation-state", "CURIUM / Tortoiseshell — Iranian IRGC, IT supply chain"),
    ("G0079", "IR", "Iran", "espionage", "2016",
     ["Government", "Technology"],
     "nation-state", "DarkHydrus — Iranian APT targeting Middle East government"),
    ("G1005", "IR", "Iran", "espionage", "2020",
     ["Government", "Technology", "NGO"],
     "nation-state", "POLONIUM — Iranian-linked, targeting Israel"),
    ("G0090", "IR", "Iran", "espionage", "2018",
     ["Government", "Technology"],
     "nation-state", "WIRTE — Iranian-linked APT targeting Middle East"),

    # -------------------------------------------------------------------------
    # Pakistan
    # -------------------------------------------------------------------------
    ("G1002", "PK", "Pakistan", "espionage", "2013",
     ["Government", "Military", "Energy"],
     "nation-state", "BITTER — Pakistani APT targeting China and South Asia"),
    ("G0142", "PK", "Pakistan", "espionage", "2013",
     ["Government", "Military"],
     "nation-state", "Confucius — Pakistani APT targeting India and SE Asia"),
    ("G0040", "PK", "Pakistan", "espionage", "2009",
     ["Government", "Defense", "Technology"],
     "nation-state", "Patchwork / Dropping Elephant — Indian or Pakistani APT"),
    ("G0042", "PK", "Pakistan", "espionage", "2013",
     ["Government", "Military"],
     "nation-state", "MONSOON / Confucius overlap — South Asian espionage"),
    ("G1008", "PK", "Pakistan", "espionage", "2019",
     ["Government", "Defense"],
     "nation-state", "SideCopy — Pakistani APT mimicking Sidewinder TTPs"),

    # -------------------------------------------------------------------------
    # India
    # -------------------------------------------------------------------------
    ("G0121", "IN", "India", "espionage", "2012",
     ["Government", "Military", "Energy"],
     "nation-state", "Sidewinder / Rattlesnake — Indian APT targeting Pakistan and China"),

    # -------------------------------------------------------------------------
    # Vietnam
    # -------------------------------------------------------------------------
    ("G1028", "VN", "Vietnam", "espionage", "2014",
     ["Government", "Media", "NGO"],
     "nation-state", "APT-C-23 / Two-tailed Scorpion — Palestinian/Middle East focus (reassigned)"),

    # -------------------------------------------------------------------------
    # Colombia / South America
    # -------------------------------------------------------------------------
    ("G0099", "CO", "Colombia", "espionage", "2018",
     ["Government", "Military", "Financial"],
     "unknown", "APT-C-36 / Blind Eagle — South American APT targeting Colombia"),
    ("G0095", "VE", "Venezuela", "espionage", "2010",
     ["Government", "Military"],
     "nation-state", "Machete — Spanish-speaking APT targeting Latin America"),

    # -------------------------------------------------------------------------
    # Lebanon / Middle East
    # -------------------------------------------------------------------------
    ("G0070", "LB", "Lebanon", "espionage", "2012",
     ["Government", "Military", "Telecom"],
     "nation-state", "Dark Caracal — Lebanese GDGS intelligence"),
    ("G0123", "LB", "Lebanon", "espionage", "2012",
     ["Government", "Technology"],
     "nation-state", "Volatile Cedar / Lebanese Cedar — Lebanese APT"),

    # -------------------------------------------------------------------------
    # Israel
    # -------------------------------------------------------------------------
    ("G0063", "IL", "Israel", "espionage", "2016",
     ["Government", "NGO", "Technology"],
     "nation-state", "BlackOasis — likely Israeli or Western nation-state (NSO Group nexus)"),

    # -------------------------------------------------------------------------
    # UAE / Gulf
    # -------------------------------------------------------------------------
    ("G0038", "AE", "UAE", "espionage", "2012",
     ["Government", "Journalists", "Activists"],
     "nation-state", "Stealth Falcon / Project Raven — UAE signals intelligence"),

    # -------------------------------------------------------------------------
    # Criminal / financially motivated (no clear nation-state attribution)
    # -------------------------------------------------------------------------
    ("G0008", "RU", "Russia", "financial", "2013",
     ["Financial", "Hospitality", "Retail"],
     "criminal", "Carbanak / FIN7 overlap — Russian cybercriminal, banking trojans"),
    ("G0080", "RU", "Russia", "financial", "2016",
     ["Financial"],
     "criminal", "Cobalt Group — Russian cybercriminal, ATM/SWIFT fraud"),
    ("G0037", "RU", "Russia", "financial", "2011",
     ["Financial", "Retail", "Hospitality"],
     "criminal", "FIN6 — Russian cybercriminal, payment card theft"),
    ("G0046", "RU", "Russia", "financial", "2013",
     ["Financial", "Hospitality", "Restaurant"],
     "criminal", "FIN7 / Carbanak — Russian cybercriminal, OFAC sanctioned"),
    ("G0061", "RU", "Russia", "financial", "2016",
     ["Financial", "Retail"],
     "criminal", "FIN8 — Russian cybercriminal, POS malware"),
    ("G0092", "RU", "Russia", "financial", "2014",
     ["Financial", "Retail", "Technology"],
     "criminal", "TA505 / Evil Corp overlap — Russian cybercriminal, Clop ransomware"),
    ("G0102", "RU", "Russia", "financial", "2016",
     ["Financial", "Healthcare", "Government"],
     "criminal", "Wizard Spider / TEMP.MixMaster — Russian cybercriminal, Ryuk/Conti"),
    ("G0115", "RU", "Russia", "financial", "2018",
     ["Financial", "Healthcare", "Government"],
     "criminal", "GOLD SOUTHFIELD — REvil/Sodinokibi ransomware operators"),
    ("G0048", "RU", "Russia", "financial", "2015",
     ["Financial", "Technology"],
     "criminal", "RTM — Russian cybercriminal targeting finance"),
    ("G0091", "RU", "Russia", "financial", "2016",
     ["Financial"],
     "criminal", "Silence — Russian cybercriminal targeting banks"),
    ("G1024", "US", "Unknown", "financial", "2023",
     ["Technology", "Healthcare", "Financial"],
     "criminal", "Akira — ransomware group, likely English-speaking criminal"),
    ("G1032", "US", "Unknown", "financial", "2023",
     ["Healthcare", "Technology", "Financial"],
     "criminal", "INC Ransom — ransomware group"),
    ("G1004", "US", "Unknown", "financial", "2021",
     ["Technology", "Telecom", "Government"],
     "criminal", "LAPSUS$ — English-speaking extortion group, loosely organized"),
    ("G1015", "US", "Unknown", "financial", "2022",
     ["Financial", "Telecom", "Technology"],
     "criminal", "Scattered Spider / Starfraud — English-speaking social engineering"),
    ("G0127", "RU", "Russia", "financial", "2018",
     ["Financial", "Retail"],
     "criminal", "TA551 / Shathak — Russian cybercriminal, malware distribution"),
    ("G1037", "RU", "Russia", "financial", "2022",
     ["Financial", "Technology"],
     "criminal", "TA577 — ransomware affiliate group"),
    ("G1038", "RU", "Russia", "financial", "2022",
     ["Technology", "Financial"],
     "criminal", "TA578 — financially motivated threat actor"),
    ("G1040", "US", "Unknown", "financial", "2022",
     ["Healthcare", "Financial", "Manufacturing"],
     "criminal", "Play — ransomware group"),
    ("G1039", "RU", "Russia", "financial", "2018",
     ["Financial", "Legal", "Technology"],
     "criminal", "RedCurl — Russian corporate espionage for hire"),
    ("G1026", "BR", "Brazil", "financial", "2019",
     ["Financial"],
     "criminal", "Malteiro — Brazilian cybercriminal targeting Latin America banking"),

    # -------------------------------------------------------------------------
    # Hacktivism / mixed
    # -------------------------------------------------------------------------
    ("G0043", "SY", "Syria", "hacktivism", "2011",
     ["Government", "Media", "Activists"],
     "hacktivist", "Group5 — Syrian Electronic Army linked"),
    ("G0021", "PS", "Palestine", "espionage", "2012",
     ["Government", "Media", "NGO"],
     "nation-state", "Molerats / Gaza Cybergang — Palestinian APT"),
    ("G1021", "IR", "Iran", "financial", "2021",
     ["Technology", "Financial"],
     "criminal", "Cinnamon Tempest / DEV-0401 — Iranian ransomware operator"),

    # -------------------------------------------------------------------------
    # South Korea
    # -------------------------------------------------------------------------
    ("G0029", "CN", "China", "espionage", "2012",
     ["Government", "NGO", "Think Tanks"],
     "nation-state", "Scarlet Mimic — Chinese APT targeting Uyghur and Tibetan activists"),

    # -------------------------------------------------------------------------
    # Belarus
    # -------------------------------------------------------------------------
    ("G0056", "RU", "Russia", "espionage", "2016",
     ["Government", "Defense", "Technology"],
     "nation-state", "PROMETHIUM / StrongPity — Turkish or Russian nexus, targeting Kurds"),

    # -------------------------------------------------------------------------
    # Turkey
    # -------------------------------------------------------------------------
    ("G0055", "TR", "Turkey", "espionage", "2016",
     ["Government"],
     "nation-state", "NEODYMIUM — Turkish APT targeting diaspora communities"),

    # -------------------------------------------------------------------------
    # Miscellaneous / regionally attributed
    # -------------------------------------------------------------------------
    ("G0097", "PK", "Pakistan", "espionage", "2018",
     ["Government", "Military"],
     "nation-state", "Bouncing Golf — Pakistani APT targeting Middle East military"),
    ("G0052", "IL", "Israel", "espionage", "2014",
     ["Government", "Technology"],
     "nation-state", "CopyKittens — Israeli or Iranian nexus APT"),
    ("G0017", "CN", "China", "espionage", "2013",
     ["Government", "Technology"],
     "nation-state", "DragonOK — Chinese APT targeting Japan and Taiwan"),
    ("G0031", "CN", "China", "espionage", "2010",
     ["Government", "Defense"],
     "nation-state", "Dust Storm — Chinese APT targeting Japan"),
    ("G0120", "RU", "Russia", "financial", "2018",
     ["Financial", "Cryptocurrency"],
     "criminal", "Evilnum — likely Eastern European, targeting fintech"),
    ("G0051", "CA", "Canada", "financial", "2013",
     ["Financial", "Energy"],
     "criminal", "FIN10 — Canadian or North American cybercriminal"),
    ("G1016", "MX", "Mexico", "financial", "2016",
     ["Financial"],
     "criminal", "FIN13 / Elephant Beetle — financially motivated, Latin America"),
    ("G0085", "RU", "Russia", "espionage", "2013",
     ["Financial", "Healthcare"],
     "criminal", "FIN4 — financially motivated, insider trading"),
    ("G0053", "RU", "Russia", "financial", "2013",
     ["Financial", "Retail"],
     "criminal", "FIN5 — Eastern European cybercriminal, POS theft"),
    ("G0125", "CN", "China", "espionage", "2021",
     ["Technology", "Defense", "Government"],
     "nation-state", "HAFNIUM — Chinese MSS, Exchange Server zero-days"),
    ("G1001", "IR", "Iran", "espionage", "2017",
     ["Energy", "Technology", "Telecom"],
     "nation-state", "HEXANE / Lyceum — Iranian APT targeting oil and gas"),
    ("G0126", "JP", "Japan", "espionage", "2016",
     ["Government", "Defense", "Technology"],
     "nation-state", "Higaisa — South Korean or Japanese APT"),
    ("G0072", "KP", "North Korea", "espionage", "2018",
     ["NGO", "Healthcare"],
     "nation-state", "Honeybee — North Korean APT targeting humanitarian organizations"),
    ("G0100", "RU", "Russia", "espionage", "2014",
     ["Government", "Energy", "Technology"],
     "nation-state", "Inception / Cloud Atlas — Russian APT targeting CIS countries"),
    ("G0136", "CN", "China", "espionage", "2021",
     ["Government", "Technology"],
     "nation-state", "IndigoZebra — Chinese APT targeting Central Asia"),
    ("G0004", "CN", "China", "espionage", "2010",
     ["Government", "Defense", "Technology"],
     "nation-state", "Ke3chang / APT15 / Vixen Panda — Chinese MSS"),
    ("G1004", "US", "Unknown", "financial", "2021",
     ["Technology", "Telecom"],
     "criminal", "LAPSUS$ — loosely organized English-speaking extortion group"),
    ("G0140", "PK", "Pakistan", "espionage", "2018",
     ["Government", "Aviation"],
     "nation-state", "LazyScripter — Pakistani APT targeting airlines"),
    ("G0077", "IR", "Iran", "espionage", "2017",
     ["Energy", "Government"],
     "nation-state", "Leafminer / Raspite — Iranian APT"),
    ("G0108", "US", "Unknown", "financial", "2019",
     ["Technology", "Cryptocurrency"],
     "criminal", "Blue Mockingbird — financially motivated, cryptomining"),
    ("G0135", "ZZ", "Unknown", "espionage", "2017",
     ["Government", "Technology"],
     "unknown", "BackdoorDiplomacy — likely Chinese or Middle Eastern nexus"),
    ("G0132", "ZZ", "Unknown", "financial", "2019",
     ["Government", "Technology"],
     "criminal", "CostaRicto — mercenary APT-for-hire, South Asian nexus"),
    ("G0101", "US", "Unknown", "espionage", "2019",
     ["Government", "Defense"],
     "unknown", "Frankenstein — TA505 or nation-state, spearphishing campaigns"),
    ("G0084", "ZZ", "Unknown", "espionage", "2017",
     ["Government", "Defense"],
     "unknown", "Gallmaker — likely Middle Eastern nation-state"),
    ("G0141", "CN", "China", "espionage", "2014",
     ["Government", "Technology", "Religious"],
     "nation-state", "Gelsemium — Chinese APT targeting SE Asia"),
    ("G0078", "PK", "Pakistan", "espionage", "2018",
     ["Government", "Military"],
     "nation-state", "Gorgon Group — Pakistani APT, also criminal activity"),
    ("G0104", "KP", "North Korea", "espionage", "2018",
     ["Defense", "Government"],
     "nation-state", "Sharpshooter / Rising Sun — North Korean APT"),
    ("G0122", "IR", "Iran", "espionage", "2018",
     ["Education", "Government"],
     "nation-state", "Silent Librarian / TA407 — Iranian IRGC, university targeting"),
    ("G0083", "NG", "Nigeria", "financial", "2017",
     ["Financial", "Energy"],
     "criminal", "SilverTerrier — Nigerian BEC and fraud"),
    ("G0086", "KP", "North Korea", "espionage", "2018",
     ["Education", "Government"],
     "nation-state", "Stolen Pencil — North Korean APT targeting academia"),
    ("G0062", "CN", "China", "espionage", "2013",
     ["Government", "Defense"],
     "nation-state", "TA459 — Chinese APT targeting Central Asia"),
    ("G0089", "ZZ", "Unknown", "espionage", "2017",
     ["Government", "Military"],
     "unknown", "The White Company — highly targeted, likely nation-state"),
    ("G0028", "ZZ", "Unknown", "espionage", "2013",
     ["Energy", "ICS"],
     "unknown", "Threat Group-1314 — ICS-focused, unattributed"),
    ("G0027", "CN", "China", "espionage", "2010",
     ["Government", "Defense", "Technology", "Energy"],
     "nation-state", "Threat Group-3390 / APT27 / Bronze Union — Chinese MSS"),
    ("G0076", "CN", "China", "espionage", "2017",
     ["Telecom", "Defense"],
     "nation-state", "Thrip — Chinese APT targeting satellite and telecom"),
    ("G0134", "PK", "Pakistan", "espionage", "2013",
     ["Government", "Military", "Defense"],
     "nation-state", "Transparent Tribe / APT36 — Pakistani ISI"),
    ("G0107", "ZZ", "Unknown", "espionage", "2017",
     ["Technology", "Healthcare"],
     "unknown", "Whitefly — likely Chinese, targeting Singapore"),
    ("G0124", "RU", "Russia", "espionage", "2011",
     ["Government", "Technology"],
     "nation-state", "Windigo / Ebury — Russian cybercriminal/espionage hybrid"),
    ("G0112", "ZZ", "Unknown", "espionage", "2018",
     ["Government", "Military"],
     "unknown", "Windshift — Middle Eastern APT targeting Gulf states"),
    ("G1011", "RU", "Russia", "financial", "2021",
     ["Technology", "Financial"],
     "criminal", "EXOTIC LILY — Russian initial access broker, Conti affiliate"),
    ("G0020", "US", "USA", "espionage", "2001",
     ["Government", "Telecom", "Energy", "Financial"],
     "nation-state", "Equation Group — NSA TAO (Five Eyes attribution)"),
    ("G0033", "BR", "Brazil", "financial", "2005",
     ["Financial"],
     "criminal", "Poseidon Group — Brazilian mercenary APT"),
    ("G0071", "ZZ", "Unknown", "espionage", "2015",
     ["Healthcare"],
     "unknown", "Orangeworm — targeting healthcare, likely nation-state or insider"),
    ("G0068", "US", "USA", "espionage", "2012",
     ["Government", "Defense", "Technology"],
     "nation-state", "PLATINUM — likely Five Eyes or Western nation-state, South Asia"),
    ("G0075", "CN", "China", "espionage", "2015",
     ["Government", "Military"],
     "nation-state", "Rancor — Chinese APT targeting SE Asia"),
    ("G0106", "CN", "China", "financial", "2018",
     ["Technology", "Cryptocurrency"],
     "criminal", "Rocke — Chinese cryptomining group"),
    ("G0105", "RU", "Russia", "financial", "2018",
     ["Financial"],
     "criminal", "DarkVishnya — Russian cybercriminal, physical implant attacks on banks"),
    ("G0012", "KP", "North Korea", "espionage", "2007",
     ["Technology", "Government", "Hospitality"],
     "nation-state", "Darkhotel — South Korean or North Korean APT"),
    ("G0109", "CN", "China", "espionage", "2020",
     ["Technology", "Government"],
     "nation-state", "Mustard Tempest / DEV-0206 — Chinese APT"),
    ("G1013", "ZZ", "Unknown", "espionage", "2021",
     ["Telecom", "Government"],
     "unknown", "Metador — highly sophisticated, unattributed"),
    ("G1020", "RU", "Russia", "financial", "2022",
     ["Technology"],
     "criminal", "Mustard Tempest — Russian initial access broker"),
    ("G0139", "RU", "Russia", "financial", "2019",
     ["Technology", "Financial", "Government"],
     "criminal", "TeamTNT — Russian-linked cloud cryptomining group"),
    ("G0011", "FR", "France", "espionage", "2011",
     ["Government", "Defense"],
     "nation-state", "PittyTiger — French or Western nation-state APT"),
    ("G0111", "CN", "China", "espionage", "2018",
     ["Government", "Technology"],
     "nation-state", "TA2541 overlap — aviation sector targeting"),
    ("G1018", "ZZ", "Unknown", "espionage", "2019",
     ["Aviation", "Government"],
     "unknown", "TA2541 — aviation-focused APT, unattributed"),
    ("G0110", "ZZ", "Unknown", "espionage", "2016",
     ["Government", "Defense"],
     "unknown", "MuddyWater overlap note"),
    ("G0074", "RU", "Russia", "espionage", "2015",
     ["Energy", "ICS", "Government"],
     "nation-state", "Dragonfly 2.0 / Berserk Bear — FSB Center 16"),
]

# =============================================================================
# Dedup (last entry for a given group_id wins)
# =============================================================================

def dedup(records):
    seen = {}
    for r in records:
        seen[r[0]] = r
    return list(seen.values())


# =============================================================================
# Main
# =============================================================================

def seed(db_path: str, dry_run: bool = False):
    records = dedup(GROUP_METADATA)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Fetch all valid group_ids
    valid_ids = {
        row[0] for row in conn.execute("SELECT group_id FROM groups").fetchall()
    }

    inserted = 0
    skipped_no_group = []
    skipped_existing = []

    for rec in records:
        group_id = rec[0]
        if group_id not in valid_ids:
            skipped_no_group.append(group_id)
            continue

        existing = conn.execute(
            "SELECT group_id FROM group_metadata WHERE group_id = ?", (group_id,)
        ).fetchone()

        if existing:
            skipped_existing.append(group_id)
            continue

        country, country_name, motivation, first_seen, target_sectors, sponsor_type, notes = rec[1:]

        if not dry_run:
            conn.execute("""
                INSERT INTO group_metadata
                    (group_id, country, country_name, motivation, first_seen,
                     target_sectors, sponsor_type, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                group_id, country, country_name, motivation, first_seen,
                json.dumps(target_sectors), sponsor_type, notes
            ))
        inserted += 1

    if not dry_run:
        conn.commit()

    conn.close()

    # Coverage report
    total_groups = len(valid_ids)
    covered = inserted + len(skipped_existing)
    unknown_count = sum(
        1 for r in records
        if r[0] in valid_ids and r[6] == "unknown"
    )

    print(f"\n{'DRY RUN — ' if dry_run else ''}Seed complete")
    print(f"  Total groups in DB : {total_groups}")
    print(f"  Records to insert  : {inserted}")
    print(f"  Already existed    : {len(skipped_existing)}")
    print(f"  Skipped (no group) : {len(skipped_no_group)}")
    print(f"  Coverage           : {covered}/{total_groups} ({100*covered//total_groups}%)")
    print(f"  sponsor_type=unknown: {unknown_count}")

    if skipped_no_group:
        print(f"\n  Group IDs not in DB: {skipped_no_group}")

    # List uncovered groups
    covered_ids = {r[0] for r in records if r[0] in valid_ids}
    uncovered = sorted(valid_ids - covered_ids)
    if uncovered:
        print(f"\n  Groups with no metadata ({len(uncovered)}):")
        rows = conn if dry_run else sqlite3.connect(db_path)
        c = sqlite3.connect(db_path)
        for gid in uncovered:
            name = c.execute(
                "SELECT name FROM groups WHERE group_id = ?", (gid,)
            ).fetchone()
            print(f"    {gid}  {name[0] if name else '?'}")
        c.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed group_metadata table")
    parser.add_argument("db_path", help="Path to threat.db")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report coverage without writing to DB")
    args = parser.parse_args()
    seed(args.db_path, dry_run=args.dry_run)
