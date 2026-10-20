# Differential test report

- Mode: `full-exact`
- Samples: 377
- Identical: 251 (66.6%)
- Different or failed: 126

| Sample | Result | Diffs | Seconds | Details |
|---|---:|---:|---:|---|
| `009c2377b67997b0da1579f4bbc822c1.exe_` | ok | 0 | 0.2 |  |
| `02179f3ba93663074740b5c0d283bae2.exe_` | ok | 0 | 2.7 |  |
| `021f49678cd633dc8cf99c61b3af3dda.exe_` | ok | 0 | 3.3 |  |
| `034b7231a49387604e81a5a5d2fe7e08f6982c418a28b719d2faace3c312ebb5.exe_` | ok | 0 | 2.0 |  |
| `03b236b23b1ec37c663527c1f53af3fe.dll_` | ok | 0 | 0.3 |  |
| `03bb32d43885e83bc56c0b2bcad6f0c5ea40402763b7057056c654990022471b.dll_` | ok | 0 | 0.2 |  |
| `055da8e6ccfe5a9380231ea04b850e18.elf_` | ok | 0 | 0.4 |  |
| `0596c4ea5aa8def47f22c85d75aaca95.exe_` | ok | 0 | 0.2 |  |
| `068a76d4823419b376d418cf03215d5c.exe_` | ok | 0 | 1.6 |  |
| `071f2d1c4c2201ee95ffe2aa965000f5f615a11a12d345e33b9fb060e5597740.dll_` | ok | 0 | 4.1 |  |
| `0731679c5f99e8ee65d8b29a3cabfc6b.exe_` | diff | 1 | 13.9 | rule 'contain loop': extra in capa-x: ['absolute:4466617'] |
| `0761142efbda6c4b1e801223de723578.dll_` | diff | 2 | 14.3 | rule 'contain loop': missing in capa-x: ['absolute:1698645968', 'absolute:1698646304', 'absolute:1698646688', 'absolute:1698968192', 'absolute:1698971584', 'absolute:1698981432']; extra in capa-x: ['absolute:1698449552', 'absolute:1698540464', 'absolute:1699230304', 'absolute:1699230672']<br>rule 'encode data using XOR': missing in capa-x: ['absolute:1698968773', 'absolute:1698971071', 'absolute:1698972233', 'absolute:1698974359'] |
| `0796f1c1ea0a142fc1eb7109a44c86cb.exe_` | ok | 0 | 1.5 |  |
| `07f7846bbcda782e5639292ad93907eb.exe_` | ok | 0 | 2.0 |  |
| `08ac667c65d36d6542917655571e61c8.exe_` | ok | 0 | 2.4 |  |
| `09bf850be5da44a1c3629a1f62813a83.dll_` | ok | 0 | 0.0 |  |
| `0a0882b8da225406cc838991b5f67d11.exe_` | ok | 0 | 4.0 |  |
| `0a30182ff3a6b67beb0f2cda9d0de678.exe_` | ok | 0 | 0.0 |  |
| `0a942aca9589d10f7b8f127870ca35cdd90d25c0b3449abe0434ffeb9f93f277.exe_` | ok | 0 | 2.8 |  |
| `0cd2b334aede270b14868db28211cde3.exe_` | ok | 0 | 3.9 |  |
| `0ce3bfa972ced61884ae7c1d77c7d4c45e17c7d767e669610cf2ef72b636b464.exe_` | diff | 5 | 2.6 | rule 'create or open file': missing in capa-x: ['absolute:4216788']<br>rule 'enumerate files on Windows': missing in capa-x: ['absolute:4216381']<br>rule 'enumerate files recursively': missing in capa-x: ['absolute:4216381']<br>rule 'get file size': missing in capa-x: ['absolute:4216381']<br>rule 'read file via mapping': missing in capa-x: ['absolute:4216381'] |
| `0da87fccbf7687a6c7ab38087dea8b8f32c2b1fb6546101485b7167d18d9c406.exe_` | ok | 0 | 5.7 |  |
| `0db010298586f17ee7e46f390d5724be.exe_` | ok | 0 | 2.5 |  |
| `0f33c2fec223823f84a732ceb1ad94ed2645e896095144850cf1443aeda67da6.dll_` | ok | 0 | 1.9 |  |
| `0fd8330e00aa48676d6d0c4f36e9a80b.exe_` | ok | 0 | 3.0 |  |
| `1038a23daad86042c66bfe6c9d052d27048de9653bde5750dc0f240c792d9ac8.elf_` | ok | 0 | 0.4 |  |
| `10cd7afd580ee9c222b0a87ff241d306.dll_` | ok | 0 | 0.0 |  |
| `10ebcf8c20403457a08762200015b151.exe_` | ok | 0 | 2.3 |  |
| `112f9f0e8d349858a80dd8c14190e620.exe_` | diff | 12 | 23.0 | rule 'PEB access': missing in capa-x: ['absolute:6714778']; extra in capa-x: ['absolute:6714768']<br>rule 'authenticate HMAC': missing in capa-x: ['absolute:5839968']<br>rule 'calculate modulo 256 via x86 assembly': missing in capa-x: ['absolute:7798858', 'absolute:7798981', 'absolute:7799797', 'absolute:7799871', 'absolute:7800070', 'absolute:7800240', 'absolute:7800278', 'absolute:7800344'] ...<br>rule 'contain loop': missing in capa-x: ['absolute:4514064', 'absolute:4558298', 'absolute:4559363', 'absolute:4928432', 'absolute:4931716', 'absolute:5317840', 'absolute:5350736', 'absolute:5351872'] ...; extra in capa-x: ['absolute:4777861', 'absolute:4778074', 'absolute:4778244', 'absolute:4852059', 'absolute:6435856']<br>rule 'contain obfuscated stackstrings': extra in capa-x: ['absolute:4563233', 'absolute:4564294', 'absolute:4565280', 'absolute:4566528', 'absolute:4566636', 'absolute:4567632', 'absolute:4567946', 'absolute:4568230'] ...<br>rule 'create or open file': missing in capa-x: ['absolute:5351243']<br>rule 'encode data using Base64': missing in capa-x: ['absolute:5549392']<br>rule 'encode data using XOR': missing in capa-x: ['absolute:4514619', 'absolute:5840288', 'absolute:5840368', 'absolute:5960996']<br>rule 'link function at runtime on Windows': missing in capa-x: ['absolute:5453484']<br>rule 'parse credit card information': extra in capa-x: ['absolute:4857695']<br>rule 'read file on Windows': missing in capa-x: ['absolute:5350736']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:5540272', 'absolute:5960080', 'absolute:6185632'] |
| `1195d0d18be9362fb8dd9e1738404c9d.exe_` | ok | 0 | 1.8 |  |
| `138c71e94961fe9e31cec5dfba62a639.exe_` | ok | 0 | 1.3 |  |
| `152d4c9f63efb332ccb134c6953c0104.exe_` | ok | 0 | 3.0 |  |
| `15835b6dd703e69d22d4ab941ccd5f6e78c3abc22ae123366da5e950eaa62e2b.dll_` | ok | 0 | 1.3 |  |
| `17264e3126a97c319a6a0c61e6da951e.dll_` | ok | 0 | 2.0 |  |
| `1d8fd13c890060464019c0f07b928b1a.exe_` | ok | 0 | 0.7 |  |
| `1e2791877da02d49998dea79515a89ca.dll_` | ok | 0 | 1.1 |  |
| `1e609dffd12a59ea5d5c9b3055939b1f.exe_` | ok | 0 | 1.8 |  |
| `1e9fc7f32bd5522dd0222932eb9f1d8bd0a2e132c7b46cfcc622ad97831e6128.exe_` | ok | 0 | 1.1 |  |
| `203bd48bcc18434314ad60f4c8bc21e3d3422eb0624b22b827410f9bc63b4082.exe_` | ok | 0 | 1.0 |  |
| `2055994ff75b4309eee3a49c5749d306.exe_` | ok | 0 | 1.0 |  |
| `22d0a2e4c9c2163b2bf5f0e41a2e1762.exe_` | diff | 1 | 1.1 | rule 'contain loop': missing in capa-x: ['absolute:6442460432'] |
| `232b0a8546035d9017fadf68398826edb0a1e055566bc1d356d6c9fdf1d7e485.dll_` | ok | 0 | 1.2 |  |
| `23e19068ecba68d4396bc097e0278b8eca7e7dcaa4978e34d683231ad2219ae3.exe_` | ok | 0 | 1.1 |  |
| `253309d8b3675d3cc61d4bf23aa15d4b.dll_` | diff | 1 | 7.3 | rule 'contain loop': missing in capa-x: ['absolute:268496888', 'absolute:268497039', 'absolute:268497308', 'absolute:268497317', 'absolute:268497326', 'absolute:268497393', 'absolute:268497469', 'absolute:268505017'] ...; extra in capa-x: ['absolute:268831536', 'absolute:269102074'] |
| `268d61837aa248c1d49a973612a129ce.dll_` | ok | 0 | 1.3 |  |
| `26beba7352a32b803aa19e0782011a383a1df19549910e7b2f2f244e49678524.dll_` | ok | 0 | 1.2 |  |
| `276f691a3df25481f59d79781799e35f.exe_` | diff | 1 | 2.8 | rule 'contain loop': missing in capa-x: ['absolute:5368819072', 'absolute:5368824608', 'absolute:5368826192'] |
| `2826b762b9c268601a44974ef469a671b441e798a6c3cbb40070450c6c030ba2.exe_` | diff | 1 | 1.3 | rule 'contain loop': missing in capa-x: ['absolute:7684033'] |
| `282c32269a9893c5741ca682268369421c43ac21d73b1f6c23386d61c93bf3e9.exe_` | ok | 0 | 1.3 |  |
| `2855ba06b90e7c64d9bce888e47baf6d.exe_` | ok | 0 | 1.4 |  |
| `294b8db1f2702b60fb2e42fdc50c2cee6a5046112da9a5703a548a4fa50477bc.elf_` | diff | 2 | 0.0 | rule 'contain loop': missing in capa-x: ['absolute:4221280', 'absolute:4221360', 'absolute:4221456', 'absolute:4221512', 'absolute:4221904', 'absolute:4221944', 'absolute:4222016', 'absolute:4222088']<br>rule 'unlock semaphore on Linux': missing in capa-x: ['absolute:4240664'] |
| `29a76e413ffe0f78b62926b8455082d6.exe_` | diff | 3 | 7.2 | rule 'contain loop': missing in capa-x: ['absolute:5369631488']; extra in capa-x: ['absolute:5369086768', 'absolute:5369411968', 'absolute:5369422736', 'absolute:5369477552', 'absolute:5369494912', 'absolute:5369496448', 'absolute:5369498144', 'absolute:5369499584'] ...<br>rule 'encode data using XOR': extra in capa-x: ['absolute:5369390960', 'absolute:5369391104', 'absolute:5369391200', 'absolute:5369391296', 'absolute:5369391392', 'absolute:5369391488', 'absolute:5369391584', 'absolute:5369391744'] ...<br>rule 'resolve function by parsing PE exports': extra in capa-x: ['absolute:5368866272', 'absolute:5368870336', 'absolute:5369126960'] |
| `2a584dfc657348d164274a12bff9bbd8.exe_` | ok | 0 | 1.8 |  |
| `2a7429d60040465f9bd27bbae2beef88.exe_` | ok | 0 | 0.8 |  |
| `2b8bec5bcb1777eaa155d832f7afc797.exe_` | diff | 5 | 1.0 | rule 'allocate memory': extra in capa-x: ['absolute:4205966']<br>rule 'allocate or change RW memory': extra in capa-x: ['absolute:4205966']<br>rule 'contain loop': extra in capa-x: ['absolute:4205663']<br>rule 'get socket status': extra in capa-x: ['absolute:4205663']<br>rule 'reference HTTP User-Agent string': extra in capa-x: ['absolute:4205663'] |
| `2bf18d0403677378adad9001b1243211.elf_` | diff | 2 | 0.0 | rule 'contain loop': missing in capa-x: ['absolute:4241897', 'absolute:4241918', 'absolute:4241939', 'absolute:4241960', 'absolute:4241978', 'absolute:4241996', 'absolute:4242013', 'absolute:4242036']<br>rule 'send data on socket': missing in capa-x: ['absolute:4197553'] |
| `2c83f152e09d0abaa3a3784669e75276784e50e1e202d16ab27e5741eef9ab4f.exe_` | ok | 0 | 2.4 |  |
| `2d3edc218a90f03089cc01715a9f047f.exe_` | ok | 0 | 1.3 |  |
| `2ebadd04f0ada89c36c1409b6e96423a68dd77b513db8db3da203c36d3753e5f.exe_` | ok | 0 | 0.0 |  |
| `2f43138aa75fb12ac482b486cbc98569.dll_` | ok | 0 | 0.7 |  |
| `2f7f5fb5de175e770d7eae87666f9831.elf_` | diff | 8 | 12.3 | rule 'contain loop': missing in capa-x: ['absolute:4463808', 'absolute:4464400', 'absolute:4464528', 'absolute:4464656', 'absolute:4524896', 'absolute:4528656', 'absolute:4529296', 'absolute:4529936'] ...; extra in capa-x: ['absolute:4325340', 'absolute:4463632', 'absolute:4477616', 'absolute:4479424', 'absolute:4483760', 'absolute:4485888', 'absolute:4521946', 'absolute:4547954'] ...<br>rule 'decrypt data using AES via x86 extensions': missing in capa-x: ['absolute:5351312']<br>rule 'encode data using Base64': missing in capa-x: ['absolute:6684400', 'absolute:7342448', 'absolute:7342512', 'absolute:7342816']<br>rule 'encode data using XOR': missing in capa-x: ['absolute:4863672', 'absolute:4968664', 'absolute:4969392', 'absolute:4987640', 'absolute:4988368', 'absolute:5031656', 'absolute:5032400', 'absolute:5043296'] ...; extra in capa-x: ['absolute:7030696', 'absolute:7078816']<br>rule 'encrypt data using AES via x86 extensions': missing in capa-x: ['absolute:4968320', 'absolute:4969200', 'absolute:4987296', 'absolute:4988176', 'absolute:5031312', 'absolute:5032208', 'absolute:5351312']<br>rule 'encrypt data using RC4 PRGA': missing in capa-x: ['absolute:6499941']; extra in capa-x: ['absolute:6499938', 'absolute:7087488']<br>rule 'execute syscall': missing in capa-x: ['absolute:5513352', 'absolute:7515469']<br>rule 'hash data using SHA256': missing in capa-x: ['absolute:4873680'] |
| `2f9ff544d5cc945b453356f9b20c07d8.exe_` | diff | 1 | 1.2 | rule 'find graphical window': missing in capa-x: ['absolute:4225618'] |
| `30ee31a532545d2fb456b6204dc443d5.exe_` | ok | 0 | 0.9 |  |
| `31600ad0d1a7ea615690df111ae36c73.exe_` | ok | 0 | 0.8 |  |
| `31bd8dd48ac0de3d4da340bf29f4d280.exe_` | ok | 0 | 0.9 |  |
| `31cee4f66cf3b537e3d2d37a71f339f4.exe_` | ok | 0 | 1.0 |  |
| `321338196a46b600ea330fc5d98d0699.exe_` | diff | 2 | 4.2 | rule 'contain loop': missing in capa-x: ['absolute:4226455', 'absolute:4226464', 'absolute:4226473', 'absolute:4226482', 'absolute:4252946', 'absolute:4293168', 'absolute:4294053', 'absolute:4310984']; extra in capa-x: ['absolute:4254413', 'absolute:4268312', 'absolute:4292808']<br>rule 'resolve function by parsing PE exports': extra in capa-x: ['absolute:4254413', 'absolute:4277368'] |
| `3265b2b0afc6d2ad0bdd55af8edb9b37.exe_` | diff | 1 | 4.6 | rule 'contain loop': missing in capa-x: ['absolute:4250648'] |
| `32b3678f8c29437e9ea10eab10194f66.exe_` | diff | 1 | 1.2 | rule 'contain loop': extra in capa-x: ['absolute:4278091'] |
| `32bb43f8847ecf158c1e96891ed9a28c.dll_` | diff | 1 | 0.9 | rule 'delay execution': missing in capa-x: ['absolute:268440391'] |
| `34404a3fb9804977c6ab86cb991fb130.exe_` | diff | 4 | 1.4 | rule 'contain loop': extra in capa-x: ['absolute:4202613']<br>rule 'get graphical window text': extra in capa-x: ['absolute:4202613']<br>rule 'log keystrokes': extra in capa-x: ['absolute:4202613']<br>rule 'log keystrokes via polling': extra in capa-x: ['absolute:4202613'] |
| `3446b3889a52d81119d8c482a2a282b9.exe_` | diff | 6 | 0.7 | rule 'contain loop': extra in capa-x: ['absolute:4209571']<br>rule 'delete file': extra in capa-x: ['absolute:4232750']<br>rule 'delete registry key': extra in capa-x: ['absolute:4232750']<br>rule 'delete registry value': extra in capa-x: ['absolute:4232750']<br>rule 'set registry value': extra in capa-x: ['absolute:4232750']<br>rule 'write file on Windows': extra in capa-x: ['absolute:4232750'] |
| `34dbc85ed0386e024c724c7969e8d0ff0ff0b1882508ea259c458d59657a1971.elf_` | ok | 0 | 0.1 |  |
| `3583f7f97ab207be7ab2ec0a507e2481.dll_` | ok | 0 | 0.7 |  |
| `35f9cfe5110471a82e330d904c97466a.dll_` | diff | 1 | 0.8 | rule 'contain loop': missing in capa-x: ['absolute:268508887'] |
| `368239d36d221d8877a07ab6799e643a.elf_` | ok | 0 | 0.2 |  |
| `36cc72c55f572fe02836f25516d18fed1de768e7f29af7bdf469b52a3fe2531f.exe_` | ok | 0 | 1.1 |  |
| `36f506a34b99bf4c199b3c9ec8aa02bd631feafdca20e69e33e714c269ddb8c5.dll_` | ok | 0 | 1.7 |  |
| `378ecc1b2e60129c9f06bb6bb8042f2b95feca5f526a4c26a5c39707807fa259.exe_` | ok | 0 | 1.7 |  |
| `3808f21e56dede99bc914d90aeabe47a.exe_` | diff | 3 | 1.0 | rule 'contain loop': missing in capa-x: ['absolute:5368713792']<br>rule 'encrypt data using Salsa20 or ChaCha': missing in capa-x: ['absolute:5368713792']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:5368713792'] |
| `388021747b85453adff2680c8a0e13e230f4eeada1a1055e3fb8e09800d4fb79.dll_` | ok | 0 | 1.1 |  |
| `395eb0ddd99d2c9e37b6d0b73485ee9c.exe_` | ok | 0 | 0.8 |  |
| `39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.dll_` | diff | 5 | 1.6 | rule 'acquire debug privileges': missing in capa-x: ['absolute:268465404']<br>rule 'contain loop': missing in capa-x: ['absolute:268447920']<br>rule 'delete file': extra in capa-x: ['absolute:268447625']<br>rule 'enumerate files on Windows': missing in capa-x: ['absolute:268447920']; extra in capa-x: ['absolute:268448000']<br>rule 'enumerate files recursively': extra in capa-x: ['absolute:268448000'] |
| `39ce034911a6ebd482af5893f9bdbd95.exe_` | diff | 2 | 1.6 | rule 'contain loop': missing in capa-x: ['absolute:5368725168']<br>rule 'enumerate PE sections': missing in capa-x: ['absolute:5368845184'] |
| `3aa7ee4d67f562933bc998f352b1f319.dll_` | diff | 1 | 0.9 | rule 'manipulate console buffer': missing in capa-x: ['absolute:1884561884'] |
| `3b13b6f1d7cd14dc4a097a12e2e505c0a4cff495262261e2bfc991df238b9b04.dll_` | diff | 1 | 8.4 | rule 'contain loop': missing in capa-x: ['absolute:268563625'] |
| `3b2eba4789bd4a799fe18476a4d1ce9f37ecc4c202eb406e06425c7e792904ff.exe_` | diff | 1 | 1.3 | rule 'contain loop': extra in capa-x: ['absolute:5368916688'] |
| `3bbdf04c25fcd9876733eaa9163b3ed64d81396e7414619758d9376edf4c103e.dll_` | diff | 1 | 1.9 | rule 'contain loop': extra in capa-x: ['absolute:268622436'] |
| `3ca359f5085bb96a7950d4735b089ffe.exe_` | ok | 0 | 0.6 |  |
| `3d0d79c4715e5b6dd2f8704e4878d57646d5a92e1116aec2ef81a5679ba45cd8.exe_` | diff | 4 | 4.5 | rule 'contain loop': missing in capa-x: ['absolute:5368770944', 'absolute:5368809856', 'absolute:5368828816', 'absolute:5368834272', 'absolute:5368835056', 'absolute:5368835184', 'absolute:5368835312', 'absolute:5368835456'] ...; extra in capa-x: ['absolute:5368772928', 'absolute:5368775136', 'absolute:5368778608', 'absolute:5368810416', 'absolute:5368810704', 'absolute:5368811520', 'absolute:5368811744', 'absolute:5368813408'] ...<br>rule 'manipulate console buffer': missing in capa-x: ['absolute:5369060368', 'absolute:5369061520', 'absolute:5369061648']<br>rule 'query environment variable': missing in capa-x: ['absolute:5368827376']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:5369056720', 'absolute:5369205424'] |
| `3d5a99114b24e4373b77077072e4ed52ffce9e2607ec6fe4ed2f08d3b1c59026.dll_` | ok | 0 | 1.1 |  |
| `3d760b6fc84571c928bed835863fc302.exe_` | ok | 0 | 1.0 |  |
| `3da7c2c70a2d93ac4643f20339d5c7d61388bddd77a4a5fd732311efad78e535.elf_` | diff | 2 | 1.8 | rule 'contain loop': missing in capa-x: ['absolute:134521392', 'absolute:134522688', 'absolute:134523504', 'absolute:134524000', 'absolute:134528240', 'absolute:134540368', 'absolute:134541792', 'absolute:134547664'] ...; extra in capa-x: ['absolute:134518024', 'absolute:134549256', 'absolute:134613760', 'absolute:134651396', 'absolute:134656688', 'absolute:134678790', 'absolute:134720304', 'absolute:134731030'] ...<br>rule 'encrypt data using AES via x86 extensions': extra in capa-x: ['absolute:134893728', 'absolute:134893792'] |
| `3e528207ca374123f63789195a4aedde.sys_` | ok | 0 | 0.7 |  |
| `3f3bbcf8fd90bdcdcdc5494314ed4225.exe_` | diff | 1 | 3.6 | rule 'contain loop': extra in capa-x: ['absolute:4278933'] |
| `3fdfb2d522e7deecaaaf2f87420f7e75.exe_` | ok | 0 | 0.5 |  |
| `4122acca2f9ea98fc3f3ad040688e4ce.exe_` | diff | 3 | 3.2 | rule 'access PEB ldr_data': extra in capa-x: ['absolute:4406688']<br>rule 'contain loop': missing in capa-x: ['absolute:4229088', 'absolute:4230848', 'absolute:4235968', 'absolute:4237024', 'absolute:4239968', 'absolute:4240320', 'absolute:4241248', 'absolute:4241952'] ...<br>rule 'resolve function by parsing PE exports': extra in capa-x: ['absolute:4326816'] |
| `42e81cc1145ba3c1936a6cf9b8da0ccd.dll_` | ok | 0 | 0.8 |  |
| `44461306a604d2cd9883c2bb623af276.dll_` | ok | 0 | 1.0 |  |
| `44bad2e2a9e387b86870f009d01833ea4618d2a7cda5f64fa84a19f3bdf4efaf.exe_` | ok | 0 | 0.6 |  |
| `44d40faf3f1fe4ed969befab7afcd2f0.exe_` | diff | 1 | 1.5 | rule 'contain loop': extra in capa-x: ['absolute:268705280', 'absolute:268705776'] |
| `464ef2ca59782ce697bc329713698ccc.exe_` | ok | 0 | 7.5 |  |
| `477743976643213d96b66ed5041a3b12.exe_` | ok | 0 | 2.8 |  |
| `48c7ad2d9d482cb11898f2719638ceed.exe_` | ok | 0 | 0.9 |  |
| `493167e85e45363d09495d0841c30648.sys_` | ok | 0 | 0.8 |  |
| `499c2a85f6e8142c3f48d4251c9c7cd6.raw32` | ok | 0 | 0.1 |  |
| `49a34cfbeed733c24392c9217ef46bb6.exe_` | diff | 3 | 3.8 | rule 'contain loop': missing in capa-x: ['absolute:4220128', 'absolute:4224224', 'absolute:4225200', 'absolute:4227520', 'absolute:4227776', 'absolute:4228768', 'absolute:4229424', 'absolute:4231376'] ...; extra in capa-x: ['absolute:4477712']<br>rule 'encrypt data using AES via x86 extensions': extra in capa-x: ['absolute:4557104']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:4511184', 'absolute:6348224', 'absolute:6359696'] |
| `4a2992b4c7a1573bf7c74065e3bf5b0d.dll_` | diff | 1 | 1.0 | rule 'contain loop': extra in capa-x: ['absolute:268499944'] |
| `4b796a64abe7675254cd6f8a6c9b83949673158840a4a04c36e7c9068ec14cc8.dll_` | ok | 0 | 0.6 |  |
| `4b9efd882c49ef7525370ffb5197ad86.raw64` | diff | 1 | 0.1 | rule 'contain loop': extra in capa-x: ['absolute:6881280', 'absolute:6890051'] |
| `4bdd67ff852c221112337fecd0681eac.exe_` | ok | 0 | 0.8 |  |
| `4e9c546a54e40d0da89bb4616dd7f8c4.exe_` | ok | 0 | 1.4 |  |
| `4f08636da3941f6f1e70ac2bf449b69e2ddbdc23dac58fd7eab9c5fdce6a4960.dll_` | ok | 0 | 0.7 |  |
| `4f11bdb380dafa2518053c6d20147a05.exe_` | ok | 0 | 0.7 |  |
| `4f509bdfe5a2fe4320cdc070eedc0a72e12cc08f43d60a7701305b3d1408102b.exe_` | diff | 1 | 0.8 | rule 'contain loop': missing in capa-x: ['absolute:5368715824'] |
| `50d5ee1ce2ca5e30c6b1019ee64eeec2.exe_` | ok | 0 | 1.3 |  |
| `512a5575ff395389fc952d7925e72be1ca4ba86a5d4f2da50f1cbbde0b208c92.elf_` | diff | 2 | 0.3 | rule 'contain loop': extra in capa-x: ['absolute:4202532', 'absolute:4258356', 'absolute:4258705']<br>rule 'execute syscall': missing in capa-x: ['absolute:4243952'] |
| `51828683dc26bfabd3994494099ae97d.elf_` | ok | 0 | 0.1 |  |
| `52d8e95c9883cd16d7b44e3a7adc22d6.exe_` | ok | 0 | 0.9 |  |
| `54390bda109aab7fc006b8b4ead5b6c2.dll_` | diff | 1 | 5.4 | rule 'contain loop': missing in capa-x: ['absolute:268544136', 'absolute:268544210', 'absolute:268547470', 'absolute:268549353', 'absolute:268549392', 'absolute:268549413', 'absolute:268549753', 'absolute:268550013'] ... |
| `54ac78733552a62d1d05ea4ba3fc604bb49fe000d7fc948da45335b726e64d75.dll_` | diff | 1 | 0.8 | rule 'contain loop': missing in capa-x: ['absolute:268478364']; extra in capa-x: ['absolute:268477796'] |
| `5589857ba6ad8cd0893f4fbba774382222a573d20a2dd71b26b3b4d64f671301.exe_` | ok | 0 | 0.9 |  |
| `559efe9f3d4864910d5c5edbaadd3972c6dfc3ba887c48aa6728b0093898563f.dll_` | diff | 3 | 2.0 | rule 'contain loop': missing in capa-x: ['absolute:268477856', 'absolute:268478240', 'absolute:268504048', 'absolute:268504922', 'absolute:268505072', 'absolute:268505322', 'absolute:268505331', 'absolute:268505340'] ...; extra in capa-x: ['absolute:268492784']<br>rule 'reference SQL statements': missing in capa-x: ['absolute:268819403']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:268808222', 'absolute:268810544', 'absolute:268810682', 'absolute:268810708', 'absolute:268810867', 'absolute:268811013', 'absolute:268811479', 'absolute:268811533'] ... |
| `55d77ab16377a8a314982f723fcc6fae.exe_` | diff | 1 | 3.3 | rule 'contain loop': missing in capa-x: ['absolute:4471433', 'absolute:4471454']; extra in capa-x: ['absolute:4351944'] |
| `563653399b82cd443f120eceff836ea3678d4cf11d9b351bb737573c2d856299.exe_` | ok | 0 | 0.6 |  |
| `573174640974b288d9d161cf4d29387cd7dbf7d80a80f5547df887f9836df8fb.exe_` | ok | 0 | 0.6 |  |
| `5789181cba467fa940cdce809b88b9bf7e0e9d4e079e32a68d2b911a8cc47da9.exe_` | diff | 5 | 1.8 | rule 'contain loop': extra in capa-x: ['absolute:4221621', 'absolute:4223939', 'absolute:4224364', 'absolute:4224384', 'absolute:4464904']<br>rule 'get disk information': extra in capa-x: ['absolute:4224364', 'absolute:4224384']<br>rule 'get service handle': extra in capa-x: ['absolute:4223939']<br>rule 'hash data using SHA1': extra in capa-x: ['absolute:4364448']<br>rule 'hash data using SHA256': extra in capa-x: ['absolute:4364448'] |
| `580c37831fe98a254eb6c61c692c70d8.exe_` | diff | 1 | 0.7 | rule 'contain loop': extra in capa-x: ['absolute:4201346'] |
| `58adc2e97fbee01b71073ccd7ff1b9a4.exe_` | ok | 0 | 0.8 |  |
| `592cfd22bba96ef3aab566fe7bf82aff5e1b4130856d1f7f847d03d4689af7e7.exe_` | ok | 0 | 0.9 |  |
| `59a6c5036241a2f604e755bf523eb084.exe_` | ok | 0 | 1.1 |  |
| `5a2f620f29ca2f44fc22df67b674198f.exe_` | diff | 1 | 1.1 | rule 'contain loop': missing in capa-x: ['absolute:4201885'] |
| `5b3968b47eb16a1cb88525e3b565eab1.exe_` | ok | 0 | 1.2 |  |
| `5b99fa01c72cebc53a76cc72e9581189.dll_` | ok | 0 | 1.0 |  |
| `5d7c34b6854d48d3da4f96b71550a221.exe_` | ok | 0 | 0.8 |  |
| `5dd0b130d5c3d40c69e3972f39fd7d62.exe_` | diff | 4 | 14.1 | rule 'PEB access': missing in capa-x: ['absolute:4527646']; extra in capa-x: ['absolute:4253980', 'absolute:4433456']<br>rule 'calculate modulo 256 via x86 assembly': missing in capa-x: ['absolute:4242841']; extra in capa-x: ['absolute:4434641']<br>rule 'contain loop': missing in capa-x: ['absolute:4242676', 'absolute:4261804', 'absolute:4340896', 'absolute:4525792', 'absolute:4526596']; extra in capa-x: ['absolute:4235856', 'absolute:4253640', 'absolute:4253938', 'absolute:4432808', 'absolute:4433456', 'absolute:4497852', 'absolute:4513314', 'absolute:4525840']<br>rule 'get common file path': extra in capa-x: ['absolute:4524616'] |
| `5e6764534b3a1e4d3abacc4810b6985d.exe_` | ok | 0 | 1.0 |  |
| `5f66b82558ca92e54e77f216ef4c066c.exe_` | diff | 3 | 2.7 | rule 'contain loop': missing in capa-x: ['absolute:4255956', 'absolute:4257780', 'absolute:4257810', 'absolute:4257831', 'absolute:4258168', 'absolute:4258435', 'absolute:4258773', 'absolute:4258828'] ...<br>rule 'link function at runtime on Windows': missing in capa-x: ['absolute:4518379']<br>rule 'reference SQL statements': missing in capa-x: ['absolute:4339498']; extra in capa-x: ['absolute:4328065'] |
| `5fbbfeed28b258c42e0cfeb16718b31c.exe_` | diff | 4 | 4.0 | rule 'allocate thread local storage': extra in capa-x: ['absolute:4721360']<br>rule 'contain loop': missing in capa-x: ['absolute:4276340', 'absolute:4276412']; extra in capa-x: ['absolute:4276356']<br>rule 'delete file': missing in capa-x: ['absolute:4276340', 'absolute:4276412']; extra in capa-x: ['absolute:4276356']<br>rule 'set thread local storage value': extra in capa-x: ['absolute:4721360'] |
| `638dcc3d37b3a574044233c9637d7288.exe_` | ok | 0 | 0.7 |  |
| `648fc498110b11b4313a47a776e6ba40.exe_` | diff | 2 | 9.4 | rule 'contain loop': missing in capa-x: ['absolute:5166056', 'absolute:6266984']; extra in capa-x: ['absolute:4385540', 'absolute:4415188', 'absolute:4418108', 'absolute:4420076', 'absolute:4421440', 'absolute:4425096', 'absolute:4449932', 'absolute:4450720'] ...<br>rule 'encrypt data using RC4 PRGA': extra in capa-x: ['absolute:4741136'] |
| `64ce9ab801d9bef5284b408c3373dd30ba2dc6952c0950c8049be067b5f24530.dll_` | ok | 0 | 0.9 |  |
| `64d9f7d96b99467f36e22fada623c3bb.dll_` | ok | 0 | 0.8 |  |
| `64e9f62840db2f65fc717cfaf99081f9.dll_` | diff | 1 | 1.4 | rule 'contain loop': extra in capa-x: ['absolute:268694072'] |
| `658b0502b53f718bd0611a638dfd5969.exe_` | ok | 0 | 0.6 |  |
| `659a539cfff56e5450af76f8696b7122d6a22b1d7dbe5121c7b6308eb6ec1c3a.exe_` | ok | 0 | 1.3 |  |
| `65b1ea6e5254d458c602504ceeda5e05.exe_` | ok | 0 | 1.0 |  |
| `66602b5fab602cb4e6f754748d249542.exe_` | diff | 1 | 3.5 | rule 'contain loop': missing in capa-x: ['absolute:4234800', 'absolute:4234912'] |
| `67f8302a2fd28d15f62d6d20d748bfe350334e5353cbdef112bd1f8231b5599d.exe_` | ok | 0 | 0.7 |  |
| `684cc28e6a7fbd12f23dbc563f06306555ebb870bd727ad60839d4ff26e7f3b2.exe_` | diff | 4 | 6.4 | rule 'PEB access': missing in capa-x: ['absolute:5369088625']<br>rule 'access PEB ldr_data': missing in capa-x: ['absolute:5369088625']<br>rule 'contain loop': missing in capa-x: ['absolute:5368801648', 'absolute:5368802160', 'absolute:5369078736', 'absolute:5369509568', 'absolute:5369510032', 'absolute:5369513792', 'absolute:5369514256', 'absolute:5369518816'] ...; extra in capa-x: ['absolute:5369009392', 'absolute:5369009552', 'absolute:5369053264', 'absolute:5369054176', 'absolute:5369075488', 'absolute:5369096064']<br>rule 'get number of processors': missing in capa-x: ['absolute:5369077472', 'absolute:5369078736', 'absolute:5369078992', 'absolute:5369083696', 'absolute:5369084416', 'absolute:5369085680', 'absolute:5369087568', 'absolute:5369088048'] ...; extra in capa-x: ['absolute:5369010512', 'absolute:5369096064'] |
| `6a352c3e55e8ae5ed39dc1be7fb964b1.dll_` | diff | 1 | 2.4 | rule 'contain loop': extra in capa-x: ['absolute:268539488'] |
| `6b25f1e754ef486bbb28a66d46bababe.exe_` | ok | 0 | 2.5 |  |
| `6be0ae5cb7c3155f70d608fc7670d2d9.exe_` | ok | 0 | 3.7 |  |
| `6c440a5ce8509984dcc4e703d0e4dd9bffc4efd769dc8543f8d2e0cd86452822.dll_` | ok | 0 | 1.0 |  |
| `6cc148363200798a12091b97a17181a1.exe_` | diff | 6 | 17.3 | rule 'contain loop': missing in capa-x: ['absolute:5368739328', 'absolute:5368747392', 'absolute:5368749392', 'absolute:5368754304', 'absolute:5368757184', 'absolute:5368779456', 'absolute:5368780800', 'absolute:5368786176'] ...<br>rule 'decrypt data using AES via x86 extensions': missing in capa-x: ['absolute:5368747392', 'absolute:5368754304']<br>rule 'encrypt data using AES': missing in capa-x: ['absolute:5368717408', 'absolute:5368718864']<br>rule 'encrypt data using AES via x86 extensions': missing in capa-x: ['absolute:5368747392', 'absolute:5368749392', 'absolute:5368754304', 'absolute:5368757184']<br>rule 'reference AES constants': missing in capa-x: ['absolute:5368717408', 'absolute:5368718864']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:5368773280'] |
| `6cd1315f6f2fa4f8ee2b98bb3ca0a994.exe_` | ok | 0 | 1.1 |  |
| `6ee9bb8b897c2d69f797646d5f94de0f.elf_` | diff | 1 | 0.2 | rule 'contain loop': extra in capa-x: ['absolute:33585456', 'absolute:33617360', 'absolute:33617568'] |
| `6f99a2c8944cb02ff28c6f9ced59b161.exe_` | diff | 1 | 4.6 | rule 'contain loop': extra in capa-x: ['absolute:4230064'] |
| `6f9cb3f56d227fd57f0b75220472d744a6de894e7f74302ae39bbb164a92cdd6.exe_` | diff | 5 | 1.0 | rule 'contain loop': missing in capa-x: ['absolute:5368748852', 'absolute:5368748956']<br>rule 'delete registry key': missing in capa-x: ['absolute:5368748852', 'absolute:5368748956']<br>rule 'delete registry value': missing in capa-x: ['absolute:5368748852', 'absolute:5368748956']<br>rule 'set registry value': missing in capa-x: ['absolute:5368748852', 'absolute:5368748956']<br>rule 'terminate process': missing in capa-x: ['absolute:5368748852', 'absolute:5368748956'] |
| `6fcc13563aad936c7d0f3165351cb453.exe_` | ok | 0 | 1.3 |  |
| `70fd3347786ed7a4a43910e6778ef296.exe_` | diff | 4 | 1.3 | rule 'contain loop': missing in capa-x: ['absolute:4206932', 'absolute:4207348', 'absolute:4230160', 'absolute:4232256']; extra in capa-x: ['absolute:4204116']<br>rule 'modify access privileges': missing in capa-x: ['absolute:4232256']; extra in capa-x: ['absolute:4232349']<br>rule 'shutdown system': missing in capa-x: ['absolute:4232248']<br>rule 'terminate process': extra in capa-x: ['absolute:4204116'] |
| `71419e4d6f538b8a04ca6786e4d68f0d40204df465fe80bc6b4a0b259103e50f.dll_` | ok | 0 | 0.8 |  |
| `71a4f9b800d81ff6632b9892a6a502c412c141341e46d697a8c004e2f460913b.exe_` | ok | 0 | 0.8 |  |
| `7204e3efc2434012e13ca939db0d0b02.exe_` | ok | 0 | 0.9 |  |
| `72c8e3c8049927fa1dd53b61d9b67b9d74ab5b6c030bc38dfbe9a338a32438c9.dll_` | ok | 0 | 2.1 |  |
| `7351f8a40c5450557b24622417fc478d.elf_` | ok | 0 | 0.2 |  |
| `73ce04892e5f39ec82b00c02fc04c70f.exe_` | ok | 0 | 0.6 |  |
| `749cf36adc5513c92c7acc836d20935e3c433f3c2d5641293e7a9c57c5ce22c2.elf_` | diff | 1 | 0.0 | rule 'contain loop': extra in capa-x: ['absolute:33568095', 'absolute:33568396', 'absolute:33568412', 'absolute:33568428', 'absolute:33568444', 'absolute:33568460', 'absolute:33568476', 'absolute:33571880'] ... |
| `74e0758e469ab87f38cda7925d696ea41a122364891860e1ae30fc9ff2f68e7d.exe_` | diff | 2 | 0.8 | rule 'contain loop': missing in capa-x: ['absolute:4216951']<br>rule 'terminate process': missing in capa-x: ['absolute:4216951'] |
| `74fa32d2b277f583010b692a3f91b627.exe_` | diff | 1 | 3.9 | rule 'contain loop': missing in capa-x: ['absolute:1723572828']; extra in capa-x: ['absolute:1723431896', 'absolute:1723432304'] |
| `757139e76fae876ae50dd2c3ac11d5d8.exe_` | ok | 0 | 0.9 |  |
| `773290480d5445f11d3dc1b800728966.exe_` | ok | 0 | 0.9 |  |
| `77d87e9937546aebc1595039d730352b15fab32c72a76913f04262c6802d098f.exe_` | ok | 0 | 0.7 |  |
| `787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e.exe_` | diff | 2 | 1.7 | rule 'contain loop': missing in capa-x: ['absolute:5277168']<br>rule 'open thread': missing in capa-x: ['absolute:5254988'] |
| `79252f58d486aee8c08a8a7ebd36ae11ab5798b289e7f88e71eacf8637c340cc.dll_` | ok | 0 | 1.1 |  |
| `79abd17391adc6251ecdc58d13d76baf.dll_` | ok | 0 | 0.6 |  |
| `79cde1aa711e321b4939805d27e160be.exe_` | ok | 0 | 0.7 |  |
| `79f5cabff898d60cd614e7254d409d9c2e05184416e5c54201e2dc216998d28b.raw64` | ok | 0 | 0.1 |  |
| `7c843e75d4f02087b932fe280df9c90c.exe_` | diff | 1 | 1.6 | rule 'contain loop': missing in capa-x: ['absolute:4389707', 'absolute:4389775', 'absolute:4400772'] |
| `7ca4ce02c9d331c2cfdad7329352664c224f02ccfef826a76321831bee1e2191.dll_` | diff | 1 | 0.7 | rule 'contain loop': missing in capa-x: ['absolute:6442460460'] |
| `7cd03db8ed91a66920cc03026baa2df2a8370293b072218b9fbf6d9a21cad66b.dll_` | ok | 0 | 0.8 |  |
| `7d16efd0078f22c17a4bd78b0f0cc468.exe_` | ok | 0 | 0.6 |  |
| `7d333c9b11b06ef0982b61bfc062631bb6cf9d12d0d4f2cf1b807a25ddf62fbc.exe_` | ok | 0 | 0.6 |  |
| `7e17f0f35d50f49407841372f24fbd38.exe_` | ok | 0 | 0.8 |  |
| `7f15b1a47bbe031334e23653879e9661f4b8cde80c307548328fdd3aed87ca46.exe_` | ok | 0 | 1.2 |  |
| `7f403f7d643d90c7cbadf3ccfc68bd1badf06f89a35af5fc7811920e820bbcc9.dll_` | ok | 0 | 0.9 |  |
| `7fbc17a09cf5320c515fc1c5ba42c8b3.exe_` | ok | 0 | 1.2 |  |
| `7fd2e2e3c88675d877190abaa3002b55.dll_` | diff | 1 | 1.0 | rule 'contain loop': extra in capa-x: ['absolute:268479140'] |
| `80372de850597bd9e7e021a94f13f0a1.exe_` | ok | 0 | 0.6 |  |
| `80f166e9c0427f055c88c9ee62016a6ba6a938023ff8778f5a0b5f8d7fe7570d.dll_` | ok | 0 | 0.9 |  |
| `82bf6347acf15e5d883715dc289d8a2b.exe_` | diff | 3 | 0.0 | rule 'calculate modulo 256 via x86 assembly': missing in capa-x: ['absolute:5369418606']<br>rule 'contain loop': missing in capa-x: ['absolute:5369070608', 'absolute:5369071858', 'absolute:5369072778', 'absolute:5369073483', 'absolute:5369073933', 'absolute:5369074353', 'absolute:5369074538', 'absolute:5369075333'] ...<br>rule 'encrypt data using RC4 PRGA': missing in capa-x: ['absolute:5369078393'] |
| `8333822ed41d9f2b302cf8e21b126efc.exe_` | ok | 0 | 0.8 |  |
| `84a1212f4a91066babcf594d87a85894.exe_` | ok | 0 | 1.7 |  |
| `84f1b049fa8962b215a77f51af6714b3.dll_` | ok | 0 | 0.7 |  |
| `86a8f267cf0f51c032f7b1777eb1e51f7cd1badf3f3894e2557a3f571fca9f3d.exe_` | diff | 1 | 15.3 | rule 'contain loop': missing in capa-x: ['absolute:5369223025', 'absolute:5369231810', 'absolute:5369232560', 'absolute:5369238855', 'absolute:5369238930', 'absolute:5369241350', 'absolute:5369241585', 'absolute:5369243140'] |
| `873275ce8bf88ef66e9fa0c74b5c2a1e.exe_` | ok | 0 | 0.9 |  |
| `883bf161937f8dc6e766b07000110254.exe_` | ok | 0 | 1.0 |  |
| `8a132663bee5c2f0f5cbfebee1b55ac72934632bf32bc32d6e2dae797c9e6e35.dll_` | ok | 0 | 0.0 |  |
| `8b1682c85612db9f62eb3600a90b54e83117bb756a7456c9f82ccdcb0bf4b7e4.exe_` | ok | 0 | 0.9 |  |
| `8ba66e4b618ffdc8255f1df01f875dde6fd0561305d9f8307be7bb11d02ae363.exe_` | diff | 1 | 6.1 | rule 'contain loop': missing in capa-x: ['absolute:4375600'] |
| `91a12a4cf437589ba70b1687f5acad19.exe_` | diff | 1 | 23.3 | rule 'contain loop': extra in capa-x: ['absolute:4630902'] |
| `91b08896fbda9edb8b6f93a6bc811ec6.dll_` | ok | 0 | 0.9 |  |
| `92d8ea10ea30e8b534334a1c9857a455.exe_` | diff | 9 | 3.3 | rule 'check HTTP status code': missing in capa-x: ['absolute:5368928976']<br>rule 'contain loop': missing in capa-x: ['absolute:5368808240', 'absolute:5368918944', 'absolute:5368928976', 'absolute:5368963552', 'absolute:5368986080', 'absolute:5369111312', 'absolute:5369113552', 'absolute:5369159664'] ...; extra in capa-x: ['absolute:5368730688', 'absolute:5369102528']<br>rule 'encrypt data using RC4 PRGA': extra in capa-x: ['absolute:5369394352']<br>rule 'get disk information': missing in capa-x: ['absolute:5369023440']<br>rule 'get disk size': missing in capa-x: ['absolute:5369023440']<br>rule 'hide graphical window': missing in capa-x: ['absolute:5369165709']<br>rule 'log keystrokes': missing in capa-x: ['absolute:5369111312']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:5369274448']<br>rule 'write clipboard data': extra in capa-x: ['absolute:5368730688'] |
| `9324d1a8ae37a36ae560c37448c9705a.exe_` | ok | 0 | 0.6 |  |
| `932dab8756ad4ae9a62bde0772d952e4.exe_` | diff | 1 | 1.5 | rule 'contain loop': missing in capa-x: ['absolute:5368719236', 'absolute:5368773498'] |
| `946a99f36a46d335dec080d9a4371940.dll_` | ok | 0 | 0.7 |  |
| `9486f2c5d514c1f39833b852ab03f4c0297e9e82b456b0dccad1a2d7d15c3385.elf_` | ok | 0 | 0.2 |  |
| `94d3c854aadbcfde46b2f82801015c31.exe_` | diff | 3 | 12.9 | rule 'contain loop': missing in capa-x: ['absolute:1117239728', 'absolute:1117243776', 'absolute:1117244256']; extra in capa-x: ['absolute:1116967395', 'absolute:1117456432']<br>rule 'encode data using XOR': extra in capa-x: ['absolute:1117514682']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:1117239728'] |
| `96abcbcb4aec439ac1619b02a44b6f482241dbb7486a15138e3aada5fa01d382.dll_` | ok | 0 | 1.4 |  |
| `971e599e6e707349eccea2fd4c8e5f67.exe_` | diff | 1 | 1.5 | rule 'contain loop': missing in capa-x: ['absolute:4356760', 'absolute:4360294', 'absolute:4362551', 'absolute:4362809', 'absolute:4363155', 'absolute:4369400', 'absolute:4369849', 'absolute:4373754'] ...; extra in capa-x: ['absolute:4355170', 'absolute:4372214', 'absolute:4372258', 'absolute:4373045', 'absolute:4376581'] |
| `9879d201dc5aca863f357184cd1f170e.dll_` | ok | 0 | 1.2 |  |
| `98c37c3c23bbfb362dac7754c6ba48e75cf24d73bc963a4cdfca557b9e016909.exe_` | ok | 0 | 0.8 |  |
| `9a00ebe67d833edb70ed6dd0f4652592.dll_` | ok | 0 | 1.3 |  |
| `9b7ccaa2ae6a5b96e3110ebcbc4311f6.dll_` | diff | 1 | 4.3 | rule 'contain loop': extra in capa-x: ['absolute:268520592', 'absolute:268526288'] |
| `9bca6b99e7981208af4c7925b96fb9cf.exe_` | ok | 0 | 0.6 |  |
| `9d98f8519d9fee8219caca5b31eef0bd.exe_` | ok | 0 | 0.7 |  |
| `9dc209f66da77858e362e624d0be86b3.exe_` | ok | 0 | 1.1 |  |
| `9e4d06759f278255073f9ac7b31a115a.dll_` | ok | 0 | 0.9 |  |
| `9ed5660c6a442dbba9e2ba795ccc913c1f1517ce89854fe4287c1c8b36b21d52.exe_` | ok | 0 | 0.8 |  |
| `9efa86b43b4367bcdc1591aee59bda25.dll_` | diff | 2 | 0.0 | rule 'contain loop': missing in capa-x: ['absolute:268489849']<br>rule 'delay execution': missing in capa-x: ['absolute:268454696', 'absolute:268454825'] |
| `9f012d7e3ae8f62370278e372691eb73b878fe2280b6083e1be637b278021855.exe_` | ok | 0 | 0.6 |  |
| `9ff8e68343cc29c1036650fc153e69f7.exe_` | diff | 19 | 21.6 | rule 'PEB access': extra in capa-x: ['absolute:4263136']<br>rule 'contain loop': missing in capa-x: ['absolute:4250852', 'absolute:4283716', 'absolute:4379357', 'absolute:4447668', 'absolute:4690304', 'absolute:4693520', 'absolute:4703028']; extra in capa-x: ['absolute:4243744', 'absolute:4255444', 'absolute:4267976', 'absolute:4270744', 'absolute:4272272', 'absolute:4273572', 'absolute:4276828', 'absolute:4659848'] ...<br>rule 'create or open registry key': missing in capa-x: ['absolute:4671498']<br>rule 'create service': extra in capa-x: ['absolute:4653460']<br>rule 'create thread': missing in capa-x: ['absolute:4714524', 'absolute:4714634']<br>rule 'enumerate gui resources': extra in capa-x: ['absolute:4663880', 'absolute:4664436', 'absolute:4664728']<br>rule 'get common file path': extra in capa-x: ['absolute:4645484']<br>rule 'get graphical window text': extra in capa-x: ['absolute:4685788']<br>rule 'get hostname': extra in capa-x: ['absolute:4670024']<br>rule 'get service handle': extra in capa-x: ['absolute:4653460']<br>rule 'get system information on Windows': missing in capa-x: ['absolute:4667460']; extra in capa-x: ['absolute:4667452']<br>rule 'open process': extra in capa-x: ['absolute:4679776']<br>rule 'persist via Windows service': extra in capa-x: ['absolute:4653460']<br>rule 'receive data': missing in capa-x: ['absolute:4690304', 'absolute:4693520']<br>rule 'receive data on socket': missing in capa-x: ['absolute:4690304', 'absolute:4693520']<br>rule 'resolve DNS': missing in capa-x: ['absolute:4690304', 'absolute:4693520']<br>rule 'send data': missing in capa-x: ['absolute:4693520', 'absolute:4703028', 'absolute:4738480']; extra in capa-x: ['absolute:4703036', 'absolute:4703048']<br>rule 'send data on socket': missing in capa-x: ['absolute:4693520', 'absolute:4703028', 'absolute:4738480']; extra in capa-x: ['absolute:4703036', 'absolute:4703048']<br>rule 'terminate process': extra in capa-x: ['absolute:4679776'] |
| `Practical Malware Analysis Lab 01-01.dll_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 01-01.exe_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 01-02.exe_` | ok | 0 | 0.0 |  |
| `Practical Malware Analysis Lab 01-04.exe_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 03-02.dll_` | diff | 1 | 0.7 | rule 'delay execution': missing in capa-x: ['absolute:268448684', 'absolute:268448705', 'absolute:268448763', 'absolute:268448770'] |
| `Practical Malware Analysis Lab 03-03.exe_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 03-04.exe_` | ok | 0 | 0.7 |  |
| `Practical Malware Analysis Lab 05-01.dll_` | diff | 1 | 1.4 | rule 'create or open registry key': missing in capa-x: ['absolute:268495846'] |
| `Practical Malware Analysis Lab 06-03.exe_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 10-03.exe_` | ok | 0 | 0.7 |  |
| `Practical Malware Analysis Lab 10-03.sys_` | ok | 0 | 0.5 |  |
| `Practical Malware Analysis Lab 11-01.exe_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 11-02.dll_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 11-03.dll_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 11-03.exe_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 12-01.dll_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 12-01.exe_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 12-02.exe_` | ok | 0 | 0.0 |  |
| `Practical Malware Analysis Lab 12-03.exe_` | ok | 0 | 0.6 |  |
| `Practical Malware Analysis Lab 12-04.exe_` | ok | 0 | 0.9 |  |
| `Practical Malware Analysis Lab 14-01.exe_` | ok | 0 | 0.9 |  |
| `Practical Malware Analysis Lab 14-02.exe_` | diff | 3 | 0.7 | rule 'contain loop': extra in capa-x: ['absolute:4199872']<br>rule 'create HTTP request': extra in capa-x: ['absolute:4199616', 'absolute:4199872']<br>rule 'write file on Windows': extra in capa-x: ['absolute:4199872'] |
| `Practical Malware Analysis Lab 16-01.exe_` | ok | 0 | 0.8 |  |
| `Practical Malware Analysis Lab 16-02.exe_` | ok | 0 | 0.7 |  |
| `Practical Malware Analysis Lab 16-03.exe_` | ok | 0 | 0.7 |  |
| `Practical Malware Analysis Lab 17-02.dll_` | diff | 1 | 1.9 | rule 'create or open registry key': missing in capa-x: ['absolute:268495846'] |
| `Practical Malware Analysis Lab 17-03.exe_` | ok | 0 | 0.8 |  |
| `Practical Malware Analysis Lab 18-01.exe_` | ok | 0 | 0.8 |  |
| `Practical Malware Analysis Lab 18-03.exe_` | ok | 0 | 0.8 |  |
| `Practical Malware Analysis Lab 19-02.exe_` | ok | 0 | 1.4 |  |
| `Practical Malware Analysis Lab 20-02.exe_` | ok | 0 | 1.3 |  |
| `Practical Malware Analysis Lab 21-01.exe_` | ok | 0 | 1.3 |  |
| `a0fb20bc9aa944c3a0a6c4545c195818.exe_` | ok | 0 | 2.4 |  |
| `a1451e3108e85769302ad25c74757180.exe_` | diff | 1 | 2.7 | rule 'contain loop': extra in capa-x: ['absolute:4313174', 'absolute:4386410'] |
| `a198216798ca38f280dc413f8c57f2c2.exe_` | ok | 0 | 0.0 |  |
| `a210a5daaf487fe6c8bbaf906abce749042f15890d60b09c6cb333e54958663b.dll_` | ok | 0 | 1.4 |  |
| `a30101595f6f28ab2f4b0b2cd177c3c4d2ab34a355ab7761a3795d0887c24ada.exe_` | ok | 0 | 5.7 |  |
| `a3c0a2425ea84103adde03a92176424c.exe_` | ok | 0 | 0.8 |  |
| `a45e377dbb98a6b44fd4034bc3fff9b0.exe_` | ok | 0 | 1.0 |  |
| `a4f1f09a2b9bc87de90891da6c0fca28e2f88fd67034648060cef9862af9a3bf.dll_` | diff | 1 | 1.3 | rule 'contain loop': extra in capa-x: ['absolute:268475210'] |
| `a563c50c5fa0fd541248acaf72cc4e7d.exe_` | ok | 0 | 2.3 |  |
| `a5c70086b3bc4fe64f4e7a0aa452e620.exe_` | ok | 0 | 1.2 |  |
| `a5d66324daaee5672b913aa461d4bd3a.exe_` | ok | 0 | 2.2 |  |
| `a6594d9550d56ddeaac8b3140821e698eefb7163ba29f0119c2ef19beb6040b0.exe_` | diff | 2 | 2.4 | rule 'contain loop': missing in capa-x: ['absolute:5368857344']<br>rule 'hash data using SHA1': missing in capa-x: ['absolute:5368863968'] |
| `a6e9d94e286984b9e44c58df5eeb20cf5c08b9acff4af341ddecdfbe3ea9249d.elf_` | ok | 0 | 0.4 |  |
| `a70052c45e907820187c7e6bcdc7ecca.exe_` | diff | 9 | 2.6 | rule 'check if file exists': missing in capa-x: ['absolute:4221824']<br>rule 'contain loop': missing in capa-x: ['absolute:4215440', 'absolute:4221824', 'absolute:4225760']<br>rule 'delete file': missing in capa-x: ['absolute:4221824']<br>rule 'query environment variable': missing in capa-x: ['absolute:4215440']<br>rule 'receive data': missing in capa-x: ['absolute:4225760']<br>rule 'receive data on socket': missing in capa-x: ['absolute:4225760']<br>rule 'send data': missing in capa-x: ['absolute:4225760']<br>rule 'send data on socket': missing in capa-x: ['absolute:4225760']<br>rule 'terminate process': missing in capa-x: ['absolute:4221824']; extra in capa-x: ['absolute:4199648'] |
| `a72ac9f1cf6cc01103765f866aae2dd85ea48208fb180c01076ca982684a4032.elf_` | ok | 0 | 0.2 |  |
| `a74ee8200aace7d19dee79871bbf2ed3.exe_` | ok | 0 | 2.0 |  |
| `a90e5b3454aa71d9700b2ea54615f44b.exe_` | diff | 4 | 4.8 | rule 'contain loop': missing in capa-x: ['absolute:4362520', 'absolute:4406709', 'absolute:4468512', 'absolute:4564144', 'absolute:4603324', 'absolute:4604928', 'absolute:4619312', 'absolute:4621040'] ...; extra in capa-x: ['absolute:4227357', 'absolute:4710837']<br>rule 'delay execution': missing in capa-x: ['absolute:4362591']<br>rule 'read file on Windows': missing in capa-x: ['absolute:4524416']<br>rule 'terminate process': missing in capa-x: ['absolute:4362520'] |
| `a933a1a402775cfa94b6bee0963f4b46.dll_` | diff | 2 | 3.0 | rule 'contain loop': missing in capa-x: ['absolute:180108852']; extra in capa-x: ['absolute:180108292', 'absolute:180108784']<br>rule 'get OS version': missing in capa-x: ['absolute:180108852']; extra in capa-x: ['absolute:180108784'] |
| `ac742739cae0d411dfcb78ae99a7baee.exe_` | ok | 0 | 0.6 |  |
| `acd2d663799e8919b09e188adbb55ac655e5409bcd073e6a4b6576163e6e65d5.exe_` | ok | 0 | 0.8 |  |
| `ad4229879180e267f431ac6666b6a0a2.exe_` | diff | 1 | 3.4 | rule 'contain loop': missing in capa-x: ['absolute:5368793829', 'absolute:5368862528', 'absolute:5368864368'] |
| `af13e7583ed1b27c4ae219e344a37e2b.exe_` | ok | 0 | 0.0 |  |
| `af2f4142463f42548b8650a3adf5ceb2.dll_` | diff | 5 | 6.8 | rule 'PEB access': missing in capa-x: ['absolute:268539829']<br>rule 'access PEB ldr_data': missing in capa-x: ['absolute:268539829']<br>rule 'contain loop': missing in capa-x: ['absolute:268573872']; extra in capa-x: ['absolute:268634981']<br>rule 'get OS version': missing in capa-x: ['absolute:268539632']<br>rule 'get thread local storage value': missing in capa-x: ['absolute:268545680'] |
| `af60700383b75727f5256a0000c1476f.sys_` | ok | 0 | 0.6 |  |
| `al-khaser_x64.exe_` | ok | 0 | 4.4 |  |
| `al-khaser_x86.exe_` | diff | 3 | 0.0 | rule 'contain loop': missing in capa-x: ['absolute:4301625', 'absolute:4304105']; extra in capa-x: ['absolute:4408272', 'absolute:4493328']<br>rule 'execute anti-debugging instructions': missing in capa-x: ['absolute:4301625']; extra in capa-x: ['absolute:4493328']<br>rule 'get disk size': missing in capa-x: ['absolute:4304105']; extra in capa-x: ['absolute:4408272'] |
| `b1133d7e5599beefe992a127f6e9704176a13b7e86b4db45c3b61cf25a60d414.exe_` | ok | 0 | 0.7 |  |
| `b283415c9df06f0e53b7d452d3e5c840c5bd7a6ce734a30bae4a869a57974a0e.dll_` | ok | 0 | 0.6 |  |
| `b2ad4409323147b63e370745e5209996.exe_` | ok | 0 | 0.6 |  |
| `b43fca5283bfc7022553eff663683834.raw32` | ok | 0 | 0.1 |  |
| `b5f0524e69b3a3cf636c7ac366ca57bf5e3a8fdc8a9f01caf196c611a7918a87.elf_` | diff | 4 | 0.8 | rule 'contain loop': missing in capa-x: ['absolute:134609552', 'absolute:134621200', 'absolute:134634560', 'absolute:134636800', 'absolute:134637216', 'absolute:134648192', 'absolute:134650622', 'absolute:134653520'] ...; extra in capa-x: ['absolute:134816418', 'absolute:134853624']<br>rule 'get socket status': missing in capa-x: ['absolute:134754824', 'absolute:134776920', 'absolute:134777688']<br>rule 'query environment variable': missing in capa-x: ['absolute:134730437', 'absolute:134799136']<br>rule 'terminate process': missing in capa-x: ['absolute:134686480', 'absolute:134814592', 'absolute:134814856', 'absolute:134818703']; extra in capa-x: ['absolute:134816418', 'absolute:134879856', 'absolute:134906080'] |
| `b5f85c26d7aa5a1fb4af5821b6b5ab9b.sys_` | diff | 1 | 0.6 | rule 'contain loop': extra in capa-x: ['absolute:4228716'] |
| `b761e060c7114448d6a5fe276d4ca882c4bd702c12c4d73f6ad79b8dfac33448.exe_` | ok | 0 | 0.7 |  |
| `b766cc43d649d30e9f27aff8f7ee7de0.exe_` | ok | 0 | 0.8 |  |
| `b7841b9d5dc1f511a93cc7576672ec0c.dll_` | diff | 5 | 0.0 | rule 'acquire debug privileges': missing in capa-x: ['absolute:268465404']<br>rule 'contain loop': missing in capa-x: ['absolute:268447920']<br>rule 'delete file': extra in capa-x: ['absolute:268447625']<br>rule 'enumerate files on Windows': missing in capa-x: ['absolute:268447920']; extra in capa-x: ['absolute:268448000']<br>rule 'enumerate files recursively': extra in capa-x: ['absolute:268448000'] |
| `b7b5e1253710d8927cbe07d52d2d2e10.exe_` | ok | 0 | 0.8 |  |
| `b83480162ede09d4aa6d4850f9faa0a4c3834152752fd04cfdb22d647aa1f825.exe_` | ok | 0 | 0.9 |  |
| `b87b8637121d5e213ca02b45cbaca496bdf1fcc4bfddce48eea6e41637ffedd4.exe_` | ok | 0 | 1.3 |  |
| `b87e9dd18a5533a09d3e48a7a1efbcf6.exe_` | ok | 0 | 1.5 |  |
| `ba947eb07d8c823949316a97364d060f.exe_` | ok | 0 | 1.0 |  |
| `bb38149ff4b5c95722b83f24ca27a42b.elf_` | ok | 0 | 0.5 |  |
| `bb7922d368a9a9c8d981837b5ad988f1.exe_` | ok | 0 | 0.8 |  |
| `bc452cc1128ccf7fa9f76d83cda79132740414973600fed14509749fe946816e.exe_` | ok | 0 | 2.0 |  |
| `bc577119d1a5b7da489e7b5817d3cc38.dll_` | ok | 0 | 1.1 |  |
| `bf7a9c8bdfa6d47e01ad2b056264acc3fd90cf43fe0ed8deec93ab46b47d76cb.elf_` | diff | 2 | 0.4 | rule 'contain loop': extra in capa-x: ['absolute:134529680']<br>rule 'set current directory': extra in capa-x: ['absolute:134529680', 'absolute:134535152'] |
| `bf88e1bd4a3bde10b419a622278f1ff7.exe_` | ok | 0 | 1.0 |  |
| `bf9a888e226d8396e84e042732daf32b8c1df8fd675eb128e8da3f0d7768bea5.exe_` | diff | 1 | 0.9 | rule 'contain loop': missing in capa-x: ['absolute:5368717424'] |
| `bfb9b5391a13d0afd787e87ab90f14f5.dll_` | diff | 1 | 0.9 | rule 'connect socket': missing in capa-x: ['absolute:320108285'] |
| `c05ec67e75693127e5556eee229b88f93c7cef926cfe905dfd5464be9d305c94.exe_` | diff | 2 | 1.3 | rule 'get OS version': extra in capa-x: ['absolute:4249124']<br>rule 'link function at runtime on Windows': extra in capa-x: ['absolute:4249232'] |
| `c1969efd1e2be79909b880f4dbb8725e52efca82236f8a2165c5a8245393fcd6.exe_` | diff | 1 | 1.4 | rule 'contain loop': missing in capa-x: ['absolute:5368930510'] |
| `c29513e5a51dd24ca840f7628b872cba921976cba89dcbffd5028ba15481108c.dll_` | ok | 0 | 0.7 |  |
| `c2b2d7cea94179e6c2b6913205e37c45b67ccc0156d8f266548f7f1f95144285.elf_` | diff | 1 | 0.0 | error: direct capa analysis failed for tests/testfiles/c2b2d7cea94179e6c2b6913205e37c45b67ccc0156d8f266548f7f1f95144285.elf_ with exit status 13 |
| `c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a.dll_` | diff | 1 | 1.9 | rule 'PEB access': missing in capa-x: ['absolute:268621503'] |
| `c2bb17c12975ea61ff43a71afd9c3ff111d018af161859abae0bdb0b3dae98f9.exe_` | ok | 0 | 0.7 |  |
| `c2c3b3eea177b9411bc92a8800b40529fcd2d5c3696e71cbb2f4025429b314ee.elf_` | ok | 0 | 0.1 |  |
| `c2d46d256b8f9490c9599eea11ecef19fde7d4fdd2dea93604cee3cea8e172ac.exe_` | ok | 0 | 0.0 |  |
| `c3341b7dfbb9d43bca8c812e07b4299f.exe_` | diff | 1 | 3.2 | rule 'contain loop': missing in capa-x: ['absolute:4201920', 'absolute:4226928'] |
| `c335a9d41185a32ad918c5389ee54235.exe_` | ok | 0 | 0.0 |  |
| `c3699d0c7bd1276184249a487c1f0d7f.exe_` | diff | 1 | 0.9 | rule 'find graphical window': missing in capa-x: ['absolute:4228816'] |
| `c3ef997d330e65be1e22ba4d2622ece23391c6cfc78b2ee515f3d0c7a3083a79.exe_` | diff | 1 | 1.0 | rule 'contain loop': missing in capa-x: ['absolute:5368715600'] |
| `c40db0438a906eb0bec55093f1a0f2cc4cdc38104af0b4b4b3f18200a635c443.exe_` | diff | 5 | 3.0 | rule 'PEB access': extra in capa-x: ['absolute:4498273', 'absolute:4498609', 'absolute:4498945']<br>rule 'access PEB ldr_data': extra in capa-x: ['absolute:4381424']<br>rule 'contain loop': missing in capa-x: ['absolute:4224512', 'absolute:4229200', 'absolute:4230208', 'absolute:4233136', 'absolute:4233472', 'absolute:4234672', 'absolute:4235568', 'absolute:4237760'] ...<br>rule 'get process heap flags': extra in capa-x: ['absolute:4498273', 'absolute:4498609', 'absolute:4498945']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:4495648']; extra in capa-x: ['absolute:4326928'] |
| `c56af5561e3f20bed435fb4355cffc29.exe_` | diff | 1 | 0.9 | rule 'terminate process': missing in capa-x: ['absolute:4200249'] |
| `c66172b12971a329f8d5ff01665f204b.exe_` | diff | 1 | 1.0 | rule 'contain loop': extra in capa-x: ['absolute:4205940'] |
| `c91887d861d9bd4a5872249b641bc9f9.exe_` | ok | 0 | 1.1 |  |
| `cb0ce85efef94a4f7eacb4571ebf71b12ebbf9fb9faba96e853552822668aa22.exe_` | ok | 0 | 1.0 |  |
| `cb948b13a5046a692ec3ed8cc16a9566.exe_` | ok | 0 | 0.9 |  |
| `cc870a35c6840987dcb8c2dd46bc230a.exe_` | ok | 0 | 0.8 |  |
| `ccbf7cba35bab56563c0fbe4237fdc41.exe_` | ok | 0 | 1.0 |  |
| `cd2cba9e6313e8df2c1273593e649682.exe_` | ok | 0 | 0.7 |  |
| `ce8d7590182db2e51372a4a04d6a0927a65b2640739f9ec01cfd6c143b1110da.exe_` | ok | 0 | 1.4 |  |
| `d063b1804e8d2bb26bd2e097141c1bbc.exe_` | diff | 2 | 5.9 | rule 'hash data using SHA1': extra in capa-x: ['absolute:4488160']<br>rule 'hash data using SHA256': extra in capa-x: ['absolute:4488160'] |
| `d68ce802ef22a1bafc00c2e6675959f177ce8aed91003a053ac0c888bec42c54.dll_` | ok | 0 | 0.7 |  |
| `d7ff81ff775d4ab50d31ac1e962c8c4dea7ff9f280aa2b42ddd06760a5665002.exe_` | ok | 0 | 0.8 |  |
| `d87ba0bfce1cdb17fd243b8b1d247e88.exe_` | ok | 0 | 1.3 |  |
| `d890c1c67d83f1131c065b5eb5f263cbf54559dbcdb4562c3bde3dc30d1a3205.raw64` | ok | 0 | 0.2 |  |
| `d8d2ed4a5f13e4bda8edf89d0dd1ef57cec8b18c01fcccdb89fb745a1a2be05f.exe_` | diff | 1 | 2.5 | rule 'contain loop': missing in capa-x: ['absolute:5368770576', 'absolute:5368831264']; extra in capa-x: ['absolute:5369240676'] |
| `d9531e53036c5d04fbe7d1aeae2988c3bf0fdec63774690c5df70cc121af8de4.dll_` | diff | 3 | 3.4 | rule 'contain loop': missing in capa-x: ['absolute:268662544']<br>rule 'encode data using XOR': extra in capa-x: ['absolute:268504898', 'absolute:268505940', 'absolute:268506368']<br>rule 'hash data using SHA1': extra in capa-x: ['absolute:268788704'] |
| `d9630c174b8ff5c0aa26168df523e63e.exe_` | ok | 0 | 7.0 |  |
| `daa13ae302fe8b618ddbf590537443ef.exe_` | ok | 0 | 0.6 |  |
| `db9fe790b4e18abf55df31aa0b81e558.exe_` | ok | 0 | 0.0 |  |
| `dc4dc746d8a14060fb5fc7edd4ef5282.exe_` | ok | 0 | 0.6 |  |
| `dc7cb53c5dc2e756822328a7144c29318cb871890727eff9c8da64a01e8e782d.dll_` | ok | 0 | 0.6 |  |
| `dc9eb40429d6fa2f15cd34479cb320c8.exe_` | ok | 0 | 0.8 |  |
| `de07bd6e3ade9e4d8a36032a23de11a372bd93d39a6ef95d849e3f6f7ebac6e5.exe_` | ok | 0 | 0.8 |  |
| `df814d4b55912e4ba404c62080b3a7eda70a3c6283ea740f8a14a9116d803259.dll_` | ok | 0 | 0.6 |  |
| `e17e6a79ed614f5468d0eed758629697.elf_` | diff | 2 | 0.4 | rule 'contain loop': missing in capa-x: ['absolute:4207134', 'absolute:4207154', 'absolute:4207178', 'absolute:4207217', 'absolute:4217258', 'absolute:4217344', 'absolute:4218089', 'absolute:4218236'] ...; extra in capa-x: ['absolute:4217145', 'absolute:4227831', 'absolute:4233712']<br>rule 'encode data using Base64': missing in capa-x: ['absolute:4247073', 'absolute:4247188', 'absolute:4247303', 'absolute:4247414', 'absolute:4248351', 'absolute:4248467', 'absolute:4248583', 'absolute:4248695']; extra in capa-x: ['absolute:4250464'] |
| `e353d3fbfb5c3738a77a622adff9a416.exe_` | ok | 0 | 0.7 |  |
| `e365e3e3febb8a71267b5cd64457744a00e2d61edafb7c98b205b729315e97de.dll_` | diff | 1 | 0.7 | rule 'contain loop': extra in capa-x: ['absolute:1884753980'] |
| `e3a6fbbc9b315141da37e5abbae05bf20aa9f48d5f569c6353360f59a0315245.exe_` | diff | 1 | 0.8 | rule 'contain loop': missing in capa-x: ['absolute:5368715520'] |
| `e4c33ac3638eef68311f8ac0d72483c7.exe_` | diff | 1 | 2.1 | rule 'contain loop': missing in capa-x: ['absolute:4456815']; extra in capa-x: ['absolute:4277501'] |
| `e5369ac309f1be6d77afeeb3edab0ed8.exe_` | ok | 0 | 0.8 |  |
| `e544a4d616b60147d9774b48c2b65ef2.exe_` | ok | 0 | 1.1 |  |
| `e59ffeaf7acb0c326e452fa30bb71a36.exe_` | ok | 0 | 0.7 |  |
| `e5e8c139772efe47f738f4788ae9b3dc97960b1c006bc6a406715cab69f27cfc.elf_` | ok | 0 | 0.0 |  |
| `e69a8eb94f65480980deaf1ff5a431a6.exe_` | diff | 1 | 1.2 | rule 'contain loop': extra in capa-x: ['absolute:4279129'] |
| `e87076a1182ba40758e1d7258442c1ee23bf71ac77fad9f3babc707dce11c144.exe_` | diff | 6 | 1.4 | rule 'allocate memory': missing in capa-x: ['absolute:4415462']<br>rule 'allocate or change RWX memory': missing in capa-x: ['absolute:4415462']<br>rule 'contain loop': missing in capa-x: ['absolute:4199560', 'absolute:4202400', 'absolute:4210954', 'absolute:4213310', 'absolute:4215298', 'absolute:4223979', 'absolute:4230852', 'absolute:4232065'] ...<br>rule 'create thread': missing in capa-x: ['absolute:4415462']<br>rule 'spawn thread to RWX shellcode': missing in capa-x: ['absolute:4415462']<br>rule 'terminate process': missing in capa-x: ['absolute:4296619', 'absolute:4299707', 'absolute:4501510', 'absolute:4504727'] |
| `e999b36d5f9783178f0a4efa35a25d158f8d94325c3d6794f4153235c0aee60b.exe_` | ok | 0 | 2.5 |  |
| `ea2876e9175410b6f6719f80ee44b9553960758c7d0f7bed73c0fe9a78d8e669.dll_` | ok | 0 | 1.0 |  |
| `ea7bb99e03606702c1cbe543bb32b27e.dll_` | ok | 0 | 0.8 |  |
| `eaad7dfc78304b977d3844cc63577152.exe_` | diff | 2 | 10.3 | rule 'contain loop': missing in capa-x: ['absolute:4482655']; extra in capa-x: ['absolute:4462062', 'absolute:4481691', 'absolute:4585245']<br>rule 'delay execution': missing in capa-x: ['absolute:4465853']; extra in capa-x: ['absolute:4465859'] |
| `eb355bd63bddce02955792b4cd6539fb.dll_` | diff | 1 | 1.0 | rule 'contain loop': missing in capa-x: ['absolute:268469900'] |
| `ed888dc2f04f5eac83d6d14088d002de.exe_` | ok | 0 | 1.3 |  |
| `edb92795c06a2bde47e652639327253a1148ee675ba2f0d1d9ac8690ef1820b1.exe_` | ok | 0 | 0.8 |  |
| `ee3b869b668abec332d07c66d1a39f6dbf3a598cc1325b57a0504f8d24ac2e28.dll_` | diff | 2 | 4.5 | rule 'contain loop': extra in capa-x: ['absolute:268486048', 'absolute:268486201', 'absolute:268486249', 'absolute:268486303', 'absolute:268486359', 'absolute:268486421', 'absolute:268486475', 'absolute:268486535'] ...<br>rule 'enumerate PE sections': extra in capa-x: ['absolute:268486048', 'absolute:268486201', 'absolute:268486249', 'absolute:268486303', 'absolute:268486359', 'absolute:268486421', 'absolute:268486475', 'absolute:268486535'] ... |
| `efd1a86330cecba5d8d038fba65ac8e76955ed724986aa87cd6ca9f72f6941c7.dll_` | diff | 1 | 2.1 | rule 'contain loop': missing in capa-x: ['absolute:268460400']; extra in capa-x: ['absolute:268573184'] |
| `f03bdb9fa52f7b61ef03141fefff1498ad2612740b1fdbf6941f1c5af5eee70a.exe_` | ok | 0 | 1.0 |  |
| `f0a6a1bd6d760497623611e8297a81df.exe_` | ok | 0 | 0.9 |  |
| `f4584aed97469c461826ea17ca9b3c1d.exe_` | ok | 0 | 0.9 |  |
| `f53dfa294d6979145fbb34303cf73bb6.exe_` | diff | 1 | 0.8 | rule 'terminate process': extra in capa-x: ['absolute:5368771152'] |
| `f5449806ad50242a4df9186455434b5957f3fc2044d85a9f1d9135a542b678cc.dll_` | diff | 1 | 1.2 | rule 'contain loop': extra in capa-x: ['absolute:6442512912'] |
| `f59035192098e44b86c4648a0de4078edbe80352260276f4755d15d354f5fc58.exe_` | diff | 2 | 2.6 | rule 'contain loop': missing in capa-x: ['absolute:5368937056', 'absolute:5368937328', 'absolute:5369144816', 'absolute:5369154272', 'absolute:5369169136']<br>rule 'resolve function by parsing PE exports': missing in capa-x: ['absolute:5369144816'] |
| `f5c93ac768c8206e87544ddd76b3277c.dll_` | ok | 0 | 0.8 |  |
| `f9ac6b16273556b3a57bf2c6d7e7db97.exe_` | ok | 0 | 0.5 |  |
| `fb690a23b66d4f90dac83f1b4d6dec0074aff68d6ef62c2613120bd4d17cfbdd.exe_` | diff | 2 | 2.3 | rule 'contain loop': missing in capa-x: ['absolute:5369016288', 'absolute:5369131408', 'absolute:5369135936', 'absolute:5369257728', 'absolute:5369278096', 'absolute:5369281840', 'absolute:5369445584', 'absolute:5369459984'] ...<br>rule 'encode data using XOR': missing in capa-x: ['absolute:5369460369'] |
| `fbbaaf569b63f6398503e4f1979cabef.exe_` | diff | 1 | 1.7 | rule 'contain loop': missing in capa-x: ['absolute:4261884'] |
| `ffa48ed4b7b48897f6756c4222b2606399de0bca627cedfddf61e69986580430.elf_` | ok | 0 | 0.1 |  |
| `ffcf88ead82bdfc159376026f5a9a7da49e593497674bdb6fa7f7d03dd9398d9.exe_` | ok | 0 | 0.7 |  |
| `ffeae4a391a1d5203bd04b4161557227.exe_` | ok | 0 | 1.0 |  |
| `kernel32-64.dll_` | diff | 4 | 2.9 | rule 'PEB access': extra in capa-x: ['absolute:6442731314', 'absolute:6442731539', 'absolute:6442733928', 'absolute:6442734073', 'absolute:6442734220', 'absolute:6442734249']<br>rule 'access PEB ldr_data': extra in capa-x: ['absolute:6442733928']<br>rule 'get OS version': extra in capa-x: ['absolute:6442543504']<br>rule 'get ntdll base address': extra in capa-x: ['absolute:6442733928'] |
| `kernel32.dll_` | diff | 3 | 3.2 | rule 'contain loop': missing in capa-x: ['absolute:2111555528', 'absolute:2111687356', 'absolute:2111896296']; extra in capa-x: ['absolute:2111242672', 'absolute:2111243364']<br>rule 'contain pusha popa sequence': missing in capa-x: ['absolute:2111687356']; extra in capa-x: ['absolute:2111555592']<br>rule 'create or open file': missing in capa-x: ['absolute:2111751683'] |
| `microsocks.elf_` | ok | 0 | 0.2 |  |
| `mimikatz.exe_` | diff | 3 | 0.0 | rule 'contain loop': missing in capa-x: ['absolute:4255956', 'absolute:4257780', 'absolute:4257810', 'absolute:4257831', 'absolute:4258168', 'absolute:4258435', 'absolute:4258773', 'absolute:4258828'] ...<br>rule 'link function at runtime on Windows': missing in capa-x: ['absolute:4518379']<br>rule 'reference SQL statements': missing in capa-x: ['absolute:4339498']; extra in capa-x: ['absolute:4328065'] |
| `ping_täst.exe_` | ok | 0 | 0.5 |  |
