# APT
Retrieval for APT (Advanced Persistent Threat) Malware Analysis

## Commercial Antivirus Limitation

Technically, the modus operandi for the identification of malicious files and servers refers to consult in named blacklist databases. The VirusTotal platform issues the diagnoses regarding malignant characteristics related to files and web servers.

When it comes to suspicious files, VirusTotal issues the diagnostics provided by the world's leading commercial antivirus products. Regarding suspicious web servers, VirusTotal uses the database responsible for sensing virtual addresses with malicious practices.

VirusTotal has Application Programming Interface (APIs) that allow programmers to query the platform in an automated way and without the use of the graphical web interface. The proposed paper employs two of the APIs made available by VirusTotal. The first one is responsible for sending the investigated files to the platform server. The second API, in turn, makes commercial antivirus diagnostics available for files submitted to the platform by the first API.

Initially, the executable malwares are sent to the server belonging to the VirusTotal platform. After that, the executables are analyzed by the 89 commercial antiviruses linked to VirusTotal. Therefore, the antivirus provides its diagnostics for the executables submitted to the platform. VirusTotal allows the possibility of issuing three different types of diagnostics: malware, benign and omission.

Then, through the VirusTotal platform, the proposed paper investigates 89 commercial antiviruses with their respective results presented in Table 1. We used  1,050 malicious executables for 32-bit architecture. The goal of the work is to check the number of virtual pests cataloged by antivirus. The motivation is that the acquisition of new virtual plagues plays an important role in combating malicious applications. Therefore, the larger the database of malwares blacklisted, the better it tends to be the defense provided by the antivirus.

As for the first possibility of VirusTotal, the antivirus detects the malignity of the suspicious file. In the proposed experimental environment, all submitted executables are public domain malwares. Therefore, in the proposed study, the antivirus hits when it detects the malignity of the investigated executable. Malware detection indicates that the antivirus provides a robust service against cyber-intrusions. As larger the blacklist database, better tends to be the defense provided by the antivirus.

In the second possibility, the antivirus attests to the benignity of the investigated file. Therefore, in the proposed study, when the antivirus attests the benignity of the file, it is a case of a false negative – since all the samples are malicious. That is, the investigated executable is a malware; however, the antivirus attests to benignity in the wrong way.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

Table 1 shows the results of the evaluated 89 antivirus products. Two of these antiviruses scored above 99%. These antiviruses were: BitDefender, MicroWorld-eScan. Malware detection indicates that these antivirus programs provide a robust service against cyber-intrusions.

A major adversity in combating malicious applications is the fact that antivirus makers do not share their malware blacklists due to commercial disputes. Through Table 1 analyse, the proposed work points to an aggravating factor of this adversity: the same antivirus vendor does not even share its databases between its different antivirus programs. Note, for example, that McAfee and McAfee-GW-Edition antiviruses belong to the same company. Their blacklists, though robust, are not shared with each other. Therefore, the commercial strategies of the same company hinder the confrontation with malware. It complements that antivirus vendors are not necessarily concerned with avoiding cyber-invasions, but with optimizing their business income.

Malware detection ranged from 0% to 99.52%, depending on the antivirus being investigated. On average, the 89 antiviruses were able to detect 68.30% of the evaluated virtual pests, with a standard deviation of 27.83%. The high standard deviation indicates that the detection of malicious executables may suffer abrupt variations depending on the antivirus chosen. It is determined that the protection, against cybernetic invasions, is due to the choice of a robust antivirus with a large and updated blacklist.

As for the false negatives, the Zoner antivirus wrongly stated that malware was benign in more than 90% of cases. On average, antiviruses attested false negatives in 17.76% of the cases, with a standard deviation of 18.41%. Tackling the benignity of malware can lead to irrecoverable damage. A person or institution, for example, would rely on a particular malicious application when, in fact, it is malware.

On average, the antiviruses were missing in 13.94% of the cases, with a standard deviation of 18.37%. The omission of the diagnosis points to the limitation of these antiviruses that have limited blacklists for detection of malware in real time.

It is included as adversity, in the combat to malicious applications, the fact of the commercial antiviruses do not possess a pattern in the classification of the malwares as seen in Table 2. We choose 3 of  1,050 malwares samples in order to exemplify the miscellaneous classifications of commercial antiviruses. In this way, the time when manufacturers react to a new virtual plague is affected dramatically. As there is no a pattern, antiviruses give the names that they want, for example, a company can identify a malware as "Malware.1" and a second company identify it as "Malware12310". Therefore, the lack of a pattern, besides the no-sharing of information among the antivirus manufacturers, hinders the fast and effective detection of a malicious application.


###### Table 2 Results of 89 commercial antiviruses:

Antivirus | Deteccion (%) | False Negative (%) | Omission (%)
--------- | ------------- | ------------------ | -------------
BitDefender 99.52 0.48 0
MicroWorld-eScan 99.33 0.67 0
NANO-Antivirus 98.86 1.14 0
GData 98.76 0.57 0.67
ESET-NOD32 98.76 1.24 0
McAfee 98.67 0.86 0.48
Emsisoft 98.48 0.76 0.76
Kaspersky 98.38 1.24 0.38
AVG 98.1 0.86 1.05
MAX 97.52 0.57 1.9
Comodo 96.95 1.9 1.14
Microsoft 96.67 3.05 0.29
DrWeb 96.48 3.52 0
Ad-Aware 96.38 3.43 0.19
Webroot 96.38 0.57 3.05
Fortinet 96.38 3.62 0
VBA32 95.71 4.1 0.19
Cylance 95.52 0.1 4.38
Sophos 95.24 4.1 0.67
Ikarus 95.24 0.76 4
Panda 95.24 4.76 0
Avast 94.57 3.9 1.52
Avira 94.38 4.95 0.67
K7GW 94.19 5.81 0
Zillya 94.1 4.67 1.24
K7AntiVirus 94.1 5.81 0.1
Symantec 93.24 1.24 5.52
VIPRE 93.14 1.33 5.52
McAfee-GW-Edition 92.76 1.71 5.52
Tencent 92 5.52 2.48
ALYac 91.71 3.71 4.57
Rising 90 8.95 1.05
Yandex 89.62 8.67 1.71
AhnLab-V3 88.29 11.71 0
Jiangmin 87.9 7.33 4.76
TrendMicro-HouseCall 87.24 11.9 0.86
TrendMicro 86 12.48 1.52
Alibaba 83.33 10.48 6.19
CrowdStrike 82.48 15.24 2.29
FireEye 82.38 0.29 17.33
Qihoo-360 81.05 18.86 0.1
Paloalto 78.38 19.81 1.81
Lionic 77.62 21.14 1.24
APEX 76.38 6.57 17.05
ClamAV 75.71 23.14 1.14
Arcabit 75.71 23.52 0.76
Cybereason 75.24 0.19 24.57
Cynet 74.76 4.76 20.48
BitDefenderTheta 74.57 7.52 17.9
Sangfor 74.38 5.24 20.38
Antiy-AVL 74.29 22.29 3.43
ViRobot 72.86 27.14 0
Kingsoft 67.33 30 2.67
ZoneAlarm 66.19 32 1.81
SentinelOne 64.86 32.57 2.57
Cyren 58.48 40.95 0.57
F-Secure 54.57 44.67 0.76
Elastic 52.57 22.86 24.57
MaxSecure 47.14 31.71 21.14
Malwarebytes 46.95 52.48 0.57
eGambit 46.29 40.57 13.14
TACHYON 41.9 51.71 6.38
Bkav 39.52 58.29 2.19
CAT-QuickHeal 35.33 64.19 0.48
Invincea 22.1 6.86 71.05
Endgame 19.71 2.48 77.81
Gridinsoft 18.86 53.52 27.62
Acronis 17.52 74.48 8
F-Prot 15.14 9.52 75.33
TheHacker 14.19 3.05 82.76
SUPERAntiSpyware 13.62 86.38 0
TotalDefense 12.76 52.76 34.48
CMC 12.67 87.24 0.1
Baidu 8.67 89.52 1.81
Trapmine 7.62 8.48 83.9
AVware 7.43 0.19 92.38
nProtect 3.14 3.14 93.71
Zoner 2.19 96.19 1.62
Agnitum 1.33 0.1 98.57
Baidu-International 1.05 0.48 98.48
WhiteArmor 0.76 1.52 97.71
Norman 0.76 0 99.24
AntiVir 0.57 0 99.43
Commtouch 0.48 0.1 99.43
ByteHero 0.1 1.33 98.57
CyrenCloud 0.1 0 99.9
Avast-Mobile 0 19.71 80.29
Trustlook 0 10 90
Babable 0 11.43 88.57

###### Table 3 Miscellaneous classifications of commercial antiviruses:

Antivírus | VirusShare_001627d61a1bde3478ca4965e738dc1e | VirusShare_075efef8c9ca2f675be296d5f56406fa | VirusShare_0dab86f850fd3dafc98d0f2b401377d5
--------- | ------------------------------------------- | ------------------------------------------- | --------------------------------------------



## Materials and Methods

This paper proposes a database aiming at the classification of 32-bit benign and malware executables. There are  1,050 malicious executables, and 1,050 other benign executables. Therefore, our dataset is suitable for learning with artificial intelligence, since both classes of executables have the same amount.

Virtual plagues were extracted from databases provided by enthusiastic study groups as VirusShare. As for benign executables, the acquisition came from benign applications repositories such as sourceforge, github and sysinternals. It should be noted that all benign executables were submitted to VirusTotal and all were its benign attested by the main commercial antivirus worldwide. The diagnostics, provided by VirusTotal, corresponding to the benign and malware executables are available in the virtual address of our database.

The purpose of the creation of the database is to give full possibility of the proposed methodology being replicated by third parties in future works. Therefore, the proposed article, by making its database freely available, enables transparency and impartiality to research, as well as demonstrating the veracity of the results achieved. Therefore, it is hoped that the methodology will serve as a basis for the creation of new scientific works.
