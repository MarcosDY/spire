package sqlstore

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blang/semver/v4"
)

var (
	// migrationDumps is the state of the database at the indicated schema
	// version that the database is initialized to when doing migration tests.
	// It can be obtained by running `sqlite3 datastore.sqlite3 .dump` on a
	// pristine database created by a SPIRE release that runs that schema
	// version.
	migrationDumps = map[int]string{
		21: `
			PRAGMA foreign_keys=OFF;
			BEGIN TRANSACTION;
			CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
			CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
			INSERT INTO bundles VALUES(1,'2022-06-17 19:03:03.009646389+00:00','2022-06-17 19:58:07.693138279+00:00','spiffe://test.bloomberg.com',X'0a1b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d12ac030aa903308201a53082014aa00302010202101dbec4c288d719c3b1e4c1eec6b0ff07300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139303235335a170d3232303631373139303930335a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d0301070342000463d466afb748ca43e17bc48c60df703c61544d37ee3db2c9198f6b95e3ae03bb60ebf2d9fcecc1c571ce3a2073ef6437f13fdb58221bc912a5a3826bb7f1236da36a3068300e0603551d0f0101ff040403020186300f0603551d130101ff040530030101ff301d0603551d0e041604147dd4d080dfa6b6a702ec678c3a70664f7d0e2bbd30260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d0403020349003046022100adb7b80596f7539b49c58c612519baf6dbc91740d55d917b4b28be9b1a10ec74022100cb4098315d0f29f28bbd1e975dcc74dc4cd129a308fba0950b68ce757f7666ee12ac030aa903308201a53082014aa00302010202100fcbc5319eb905653dfb9495655bb57c300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139303630315a170d3232303631373139313231315a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d030107034200049c4213df3d4ececdbd1651d3a7eafdb062cea691fdbfa114af8a66f83385a9e08b9b0a8893ff7b6b234e2ed14d19b3f0912b3535f109abbf5945f9424b8355d5a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414481208308831170cf0b56126554b4ae6619343c830260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d0403020349003046022100b5b2677fcc3f799aaac63bc22d03e41ac9502354f3e79bc7332b26d2ab9df24602210090aa4afa1cd0e5f1abd9d39aca2515e3d9c5421b192066bd76ec4a589e952f5712aa030aa703308201a33082014aa0030201020210530d057ad2bbb05a01816c7838fa85be300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139303930325a170d3232303631373139313531325a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004c26e10c947bb87c3061793a9438a43a5b9e674fca49b94b561a8e4fd9e15d62e7b7144a3e4f7c8f78f794b39e44760b3c6c006cbf767be3aa7294b5822fcf7b5a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414d8abb8207f9152640cb0a5744b7bc8c5d7e2264730260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d04030203470030440220724460ef6272e33fd91bffca6c3855afa54781c4d32280d23a17c469480c40ab0220055303a13b35f08743ad1b67745ffd9c56e611fda7dcef6b3e9f2dce59ca590f12ab030aa803308201a43082014ba0030201020211008ce3ff7d3b9dfe8e4feba790282c0e1a300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139313231325a170d3232303631373139313832325a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004d1808631f0caffc0d25c4d8a6e7c1a110487e2ffd2ecf28e66663263f490d7503cd3039b6047655c98206f4697cd19ef03a6230e506555c320ab72b119a4105fa36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e0416041449d69ba2b790245ec9d1843510b38c0c78598afa30260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d040302034700304402205a733e62b071d94e6938dc4b4e4171996137bcd4a753a819f54c76f06da4961e022003de02a47780f307a452722800d16e579b15f04517732b205a6d4220d1b5e23412ad030aaa03308201a63082014ba003020102021100c02589802a8ded21d33235733b8a1e99300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139313532315a170d3232303631373139323133315a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d0301070342000483902bbdd8a6cd4a571e1a8c1784a050e214f1c9ae8db313496412cef6fb85a5df0d7e2949d1b1501bce8b6d2c8d6016e1982fb31def84bfab8325baca92ca7ea36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414b4320070ec91faacf8e59887f2a5a839bd86741a30260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d04030203490030460221009b4cf53f8e1eab14c39625bb6a2a68e30029808fe0e28efa0e4d81627b28816e022100a5b975c7902a26a9aa2251d0286f346e291bcd33c7f2aa1a53eeb1f8571d066a12ac030aa903308201a53082014ba003020102021100f921e3ce510fe7865f18bab76c332221300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139323635375a170d3232303631373139333330375a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004fc9060c9c42a9890c0e77c2160fad90491eb2b72a7fbb9e4178ba36bb2659ec60996135f855fa447a4ddb5c049f8a7c41dd1b21889ccdada31558d2e0f9509d9a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414062be283d174a4cf600cfb141bda849bbcdf8a3b30260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d0403020348003045022100deb384211ed707d6586406fd11d6339ba69d650ccc5780758547ed394dbab24a02202df262fb29d7bdba7ea68f59847cd7562aaf937d075e3bc63a961ce2914487d412ab030aa803308201a43082014aa003020102021070f3ce762335b82ecb6131963f3fef02300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139333030365a170d3232303631373139333631365a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004accdb39e3519326f7675ca3f40b4eebd697650bc13ccc18a661915a75809bba841028dbca7399a4776f908ae710d620a16df450a0287b5a2d5ab6bc5b508ce00a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414914f8fc7aeb504c95b918b17730aab0074f92cc630260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d0403020348003045022100dd37ef7953b808e5f797a1f51cd18de0bf53714b35e0419ab9e9e2a6ddfd4b2a02203dc345e25274608d6c3a61d063016bde9f5fd1ed4734550b562beb34aa1590e812aa030aa703308201a33082014aa003020102021040370380fc498b6750c034d3bef106ce300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139333330365a170d3232303631373139333931365a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004ba53192a0199f27a5c870ac6e3799ccd1b80c9ea559d943bb5ea60f74f68dd12911416bd8f359d92a81fe79031e006fed3d20d9bcd64859bf33c666c136412f3a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e041604144c2039bd70c9e40026ef875b4d8d813d36b33bcd30260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d0403020347003044022017f0c5904844069f307ce3b09ba741974c2999b769ff4cb6708b3085e604bdf5022024eabd358e255176e89ef66f0803d6a10967b01f64761f257535f2895ebdfac412ab030aa803308201a43082014aa003020102021034777ea2c3a639f1d949f045b2cc8037300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139333630365a170d3232303631373139343231365a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d0301070342000487fe486f685f4dd4d67e89201cfa8ffaa6e63a20f4f7f5f4ef56a3d7bf85f45b2ef72642e6ef65e6b83d9f588838e3f780d4f71d199e1c4e1ca41396ebadff44a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e0416041473c570d4cc2e2c514c7ffd14f51ffe35df5b167730260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d040302034800304502201dd2c058926d7467ffc82fdfdf30fcb22353997e23a11e3d643a4ec773678235022100fcfa2bbc7321d7ef395af90668617b1df26cc8f0df279087aa436585b16b8c4d12ac030aa903308201a53082014ba0030201020211008882a558c4bf6daffd47e4922e1eee65300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139333930365a170d3232303631373139343531365a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004466a39e286f532a88a28b521133d2283922b4f84eb7e2cfd0e57f6122703c4b436f834d6a03f6d7165eaf7791380606f395f56a0116e0cf35596f9056037a15ea36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e041604145e1384e437c6564373a830464ff9c87fefe90aff30260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d0403020348003045022009d5600c3e7d1ebc3002d745510d9958bfa92c9bd28d50aa670fac2937c1a78c0221009877463d1e34fbf8d29d6018111d996f89a5a0cfc0c4aeb885189b41cd5ba13912aa030aa703308201a33082014aa00302010202106ca146ff27eb8c68148cea38f2b35348300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139343230365a170d3232303631373139343831365a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004c8198488e5b71e4032059d587b5f00053b8443997bdeeb24f5051b93079be2cfb6ae0b141861dcfdc2824ecca60a6c4709b13685c5324e0a9d39e7dd988c8f32a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414d54ae88cb867f1408d1f9f1ce6508f417c7e501a30260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d0403020347003044022056e6148ab3456b65b16a6fcfd250242d94298c858806771310fcc9361b0a5af302204f687005b50dacfb4639ea9e58be29e829019b9fd784b8741b85ee3856fd2b0b12ac030aa903308201a53082014ba003020102021100ede6e41679c5127ba61e7c8e873d36d1300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139343530365a170d3232303631373139353131365a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004783691288c48d54a9d5cc02c0b57fa1c5a8b4a60cd9037e8ee45a5e77075c058830ddc62f5a6c3f27d85cf3972392bdc1bdb9a2d0bd9e63566d305e1db4ee9d7a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e041604140207a872660e36b39b53bb53bdb47f6e5e3d96c730260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d04030203480030450220056d677e08750138028b82295693bbf6b90b3a2b635a6721e1811240f17f7260022100e56a40b657938765c69a24a57f4e6781edebaa0bf9d66518c6a3c0e7c39b45b512ab030aa803308201a43082014aa003020102021014ffe6d2db14882d9711ffbc4da33bfb300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139343830365a170d3232303631373139353431365a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d030107034200042c983894bdd014a268d0f41c3a8565dfce7d0997caaaa90ed327fa787ce06594619262ee32099d10fc36eed46146fb5e48784c7b4fe2d4c1d057e2760298bc07a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e041604141f76ab0bc863176ff6ae86b70b3d2b1fe6078b0330260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d040302034800304502204df0f787d1434d7e87a2be669396eaef4bc92c1c14a1152720390cdd12685fee022100fef26cc35eb6f066a5629031b6597a8dc1c9e594e061d07b08310910d1fd799012ab030aa803308201a43082014aa00302010202101a93b7c8613892f615638e41dc451abb300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139353131365a170d3232303631373139353732365a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004caebebddcc0ac5cba37c463cec69460675cc469711084d011a198aa3c176dc8dc381d646372da7db26516bcc80a8b34181705f7af61b0df2afff23b298d34d8aa36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414b8b00dfd89275169097f379fdc8dbf0d53a6b0d830260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d0403020348003045022064ee7573b8d6504aba6350f1be2fc93b0927626fae7dc4fb0a3fc8bffc6af1a6022100d7260176c7407018f7e175b77c93b34a8886849dce6e60e6b1fba851d6a22b0c12ac030aa903308201a53082014ba003020102021100a77b7862dd568b2d16ec26a58e9bab1d300a06082a8648ce3d040302301e310b3009060355040613025553310f300d060355040a1306535049464645301e170d3232303631373139353735375a170d3232303631373230303430375a301e310b3009060355040613025553310f300d060355040a13065350494646453059301306072a8648ce3d020106082a8648ce3d03010703420004d2250d660fb9987fdb11c6ccb3fd4d5894029253bb12808d564028aaf7e2c1b5f624e1b7d1331770e60eba9342e4aa3588d6550e66f7f92c7d2d756b1a26c7e5a36a3068300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e041604146d7e6694715642ab9da9c42438f22af3a96ae20f30260603551d11041f301d861b7370696666653a2f2f746573742e626c6f6f6d626572672e636f6d300a06082a8648ce3d0403020348003045022100bd8ee3833c9e21becace0356017857d6de80a7b9fd3591f6f45632f9f4dd306802203f2a802a8006537d652e8729d8356206f104679955777bd60bed73948df1ff801a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004ad9db8b77cdb9a8d987ba6bb374d6ff302757b038abbbe97364170a595e087e25c5dd082a5c184c17b1a24df905788c57c997c2ac7b64acc759ccbe40a74efb412206b324d626541386e7842516a4745656d6b74784768716a50454b386856534d5618cfa2b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d0301070342000422a504324c223867a686eb5a04903f312d1c81c644d5ff02ba80649287e5253020386ee6d5dacd9e2398f29259b5ef51956aa5dd664f340d4b543392c2ecbc1712204d6749487a7178635158424b6b51746d4a7a536b4851374a6b675a72666d556a188ba4b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004594df0d913c3bdf5034e25cde0560e60e73e452e5debd38d2dc9c4aff4fbaed9475a3f873a972c5f153a6fa45c9bb66775c13bf2bb493fe3a30ab4c57c09dd7d12207644626f50355356477275634c4445725a3949416741316b36444b5a656e7a6818c0a5b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004032645c85153ab2b3a47bfe92d946356a74c71a173e2271df488143df18630f509a30442579c6399b3ed4cb6acc3961a28c823c64967b331942790d8dcbe921a1220486b414d723930436b424e4a6d746262524f5953576a456f514c667652304e6418fea6b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004e9275c7180571a4265657cb42aaf6fdcf6ef89b328e02fff513e197734ad7d533185ebc27cd4f09850fb95a7ff001496e9f5e4efe56d3b76d490bd02b9857628122042473370687742507278757534707451667131795574754e303863667a55335818bba8b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d0301070342000485d08ac889f7499d30c53c220bb76793fd9f3e7bbc487b24772bc46109e4bc578747226078032c8e57e0ea7855aa9502906b368f61ea44a503e5dedc5d14679c1220555a51625170446d3161424b5a39516165666b7246625338635471394173716618f3adb395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004ced4a54b22caaaed69fbd15cb139f35b0ed09804a3b97ba8ce91d1e744060ba525a9874a80b32e4bfbcbf1ae0979b23cf2b86050f55cae15cf55207606bf15d412205647397a68384f4153784f78494443496f4e725365373944657664454171526718b0afb395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200044c2ef4a4ffbd9e62ce32e11cd005e5933d43a6962eaea2a4443de5df71ea1e72235d0f5f52c29a0760d8cfc5095cbaec8473f02d2172f264c1eda57f331901b61220513264374377616a76366e5a6b664e367258676e6d504c57585970577969794818e4b0b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004f88dc8f97cb1a65a14e73fa96fee48719ed18f5c2ea85c6df48f8abcf9fc455636da7a2fc4642c199da04932595b1a12fd231a11f75e78e6d8ebe95458e6eea4122061466d6e624c6d44625458516465366a7a684a646d5a4d79447341695047797618a2b2b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d0301070342000470a7d4cb7f0ad669f32d30c99ac990c101ef9bb62af5e74521c17845cb87ac686c3f880a0a00cd784d0e079029092d94ac16579562e22723afb03dae8607587512205343643653756c59614d6a4d613458414b7957656e623967337758464f79327818d6b3b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004dc4f1818d94528551c626b3a24b278ad06d94a613ab43835156dcfa769536e76ca45b758fffea89968b6e3d0316b0be64b8dee0bf7481a560b4136797aeb7b5a12204c4148356d3158384b36693770557948424662457674663543707a49547034611894b5b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200048cabb93b4b5708b2ad135d06bb4ddf71630bfa86690f3e1cc20bbda31f727d3bd9bd3208a193225d221c7f600eaef75b646737813a09dc42df8d639de21f8e20122030576579575663755557474c71544c7148454c676f705556676a747352336c5818c8b6b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d0301070342000408b261f4fc9d49957510866d15c01e8118f614763e7b42ced56cb095e15f67c85ccbe1ada1cecacadeaba2dd315bbe6f1742d95ceae049782cccf681539328d512206d33675263627a7244556a687a6b336c42493731526476524b30357554354c4c18fcb7b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004aae4e1ac654a75de259da99da146cfc5de6778c21641153f166083d5d9a3cc5e09b4e860ad08fa0b1078f302793703897924c875e3498d80f4b62cdb9e544f171220465573666146665037446f4f486b43706830576a63304f35554659684165753718bab9b395061a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200046534262ad8cb1025fdb6e8dc962407e87e04a36dd0e0c07ced4d94fa5493026d55cc34666fc1db03698738396ed58e4563feadd5eea449bd5433afae32bf1f6f1220726a334b3470316658506b766476635a444c537066757337503137457830497518b7bcb39506');
			CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime,"new_serial_number" varchar(255),"new_expires_at" datetime , "can_reattest" bool);
			CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"admin" bool,"downstream" bool,"expiry" bigint,"revision_number" bigint,"store_svid" bool , "hint" varchar(255), "jwt_svid_ttl" integer);
			CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
			CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" varchar(255) );
			INSERT INTO migrations VALUES(1,'2023-06-06 12:16:04.285757-03:00','2023-06-06 12:16:04.285757-03:00',21,'1.7.0-dev-unk');
			CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "federated_trust_domains" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"bundle_endpoint_url" varchar(255),"bundle_endpoint_profile" varchar(255),"endpoint_spiffe_id" varchar(255),"implicit" bool );
			DELETE FROM sqlite_sequence;
			INSERT INTO sqlite_sequence VALUES('migrations',1);
			INSERT INTO sqlite_sequence VALUES('bundles',1);
			CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
			CREATE INDEX idx_attested_node_entries_expires_at ON "attested_node_entries"(expires_at) ;
			CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
			CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
			CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
			CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
			CREATE INDEX idx_registered_entries_expiry ON "registered_entries"("expiry") ;
			CREATE INDEX idx_registered_entries_hint ON "registered_entries"("hint") ;
			CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
			CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
			CREATE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
			CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
			CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
			CREATE UNIQUE INDEX uix_federated_trust_domains_trust_domain ON "federated_trust_domains"(trust_domain) ;
			CREATE INDEX idx_federated_registration_entries_registered_entry_id ON "federated_registration_entries"(registered_entry_id) ;
			COMMIT;
			`,
		22: `
			PRAGMA foreign_keys=OFF;
			BEGIN TRANSACTION;
			CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
			CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
			INSERT INTO bundles VALUES(1,'2023-08-29 13:35:31.53235-03:00','2023-08-29 13:35:31.613672-03:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712df030adc03308201d83082015ea0030201020214449db4c88cda977653f4d5e4770aec9b4b1e970c300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3233303531353032303530365a170d3238303531333032303530365a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b8104002203620004f57073b72f16fdec785ebd117735018227bfa2475a51385e485d0f42f540693b1768fd49ef2bf40e195ac38e48ec2bfd1cfdb51ce98cc48959d177aab0e97db0ce47e7b1c1416bb46c83577f0e2375e1dd079be4d57c8dc81410c5e5294b1867a35d305b301d0603551d0e04160414928ae360c6aaa7cf6aff8d1716b0046aa61c10ff300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040368003065023100e7843c85f844778a95c9cc1b2cdcce9bf1d0ae9d67d7e6b6c5cf3c894d37e8530f6a7711d4f2ea82c3833df5b2b6d75102300a2287548b879888c6bdf88dab55b8fc80ec490059f484b2c4177403997b463e9011b3da82f8a6e29254eee45a6293641a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200046e2ff496b28acab3401f9e9a1687bf0c0415872a6ae09ac567e846517fbad9557bc5ce4c564227bc305d5cffda6d1a8d8bf167ec8f50e8530d1f0f03a34a794d12207932527a3534416f43494834386b63436342535244524e7a486348796852576b18d3dfbda7062801');
			CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime,"new_serial_number" varchar(255),"new_expires_at" datetime,"can_reattest" bool );
			CREATE TABLE IF NOT EXISTS "attested_node_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255) );
			CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"admin" bool,"downstream" bool,"expiry" bigint,"revision_number" bigint,"store_svid" bool,"hint" varchar(255),"jwt_svid_ttl" integer );
			CREATE TABLE IF NOT EXISTS "registered_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255) );
			CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
			CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" varchar(255) );
			INSERT INTO migrations VALUES(1,'2023-08-29 13:35:31.510799-03:00','2023-08-29 13:35:31.510799-03:00',22,'1.7.2');
			CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "federated_trust_domains" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"bundle_endpoint_url" varchar(255),"bundle_endpoint_profile" varchar(255),"endpoint_spiffe_id" varchar(255),"implicit" bool );
			DELETE FROM sqlite_sequence;
			INSERT INTO sqlite_sequence VALUES('migrations',1);
			INSERT INTO sqlite_sequence VALUES('bundles',1);
			CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
			CREATE INDEX idx_attested_node_entries_expires_at ON "attested_node_entries"(expires_at) ;
			CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
			CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
			CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
			CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
			CREATE INDEX idx_registered_entries_expiry ON "registered_entries"("expiry") ;
			CREATE INDEX idx_registered_entries_hint ON "registered_entries"("hint") ;
			CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
			CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
			CREATE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
			CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
			CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
			CREATE UNIQUE INDEX uix_federated_trust_domains_trust_domain ON "federated_trust_domains"(trust_domain) ;
			CREATE INDEX idx_federated_registration_entries_registered_entry_id ON "federated_registration_entries"(registered_entry_id) ;
			COMMIT;
			`,
		23: `
			PRAGMA foreign_keys=OFF;
			BEGIN TRANSACTION;
			CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("bundle_id" integer,"registered_entry_id" integer, PRIMARY KEY ("bundle_id","registered_entry_id"));
			CREATE TABLE IF NOT EXISTS "bundles" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"data" blob );
			INSERT INTO bundles VALUES(1,'2023-08-29 13:15:25.103258-03:00','2023-08-29 13:15:25.201436-03:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712df030adc03308201d83082015ea0030201020214449db4c88cda977653f4d5e4770aec9b4b1e970c300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3233303531353032303530365a170d3238303531333032303530365a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b8104002203620004f57073b72f16fdec785ebd117735018227bfa2475a51385e485d0f42f540693b1768fd49ef2bf40e195ac38e48ec2bfd1cfdb51ce98cc48959d177aab0e97db0ce47e7b1c1416bb46c83577f0e2375e1dd079be4d57c8dc81410c5e5294b1867a35d305b301d0603551d0e04160414928ae360c6aaa7cf6aff8d1716b0046aa61c10ff300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040368003065023100e7843c85f844778a95c9cc1b2cdcce9bf1d0ae9d67d7e6b6c5cf3c894d37e8530f6a7711d4f2ea82c3833df5b2b6d75102300a2287548b879888c6bdf88dab55b8fc80ec490059f484b2c4177403997b463e9011b3da82f8a6e29254eee45a6293641a85010a5b3059301306072a8648ce3d020106082a8648ce3d030107034200045cdd2166a5ae9e1c95695558c35dabc43c44c196abbd364aff4ffaac924811d7ab4601485f61efd5422ffe67b46f9d7c0b3963f90a41183d410bd3520c7434e5122054314a6772794c4746774f516c354e6b44386e4f7051695a43436430626b7a49189dd6bda7062801');
			CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"data_type" varchar(255),"serial_number" varchar(255),"expires_at" datetime,"new_serial_number" varchar(255),"new_expires_at" datetime,"can_reattest" bool );
			CREATE TABLE IF NOT EXISTS "attested_node_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255) );
			CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"spiffe_id" varchar(255),"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255),"spiffe_id" varchar(255),"parent_id" varchar(255),"ttl" integer,"admin" bool,"downstream" bool,"expiry" bigint,"revision_number" bigint,"store_svid" bool,"hint" varchar(255),"jwt_svid_ttl" integer );
			CREATE TABLE IF NOT EXISTS "registered_entries_events" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"entry_id" varchar(255) );
			CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"token" varchar(255),"expiry" bigint );
			CREATE TABLE IF NOT EXISTS "selectors" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" varchar(255),"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "migrations" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" varchar(255) );
			INSERT INTO migrations VALUES(1,'2023-08-29 13:15:25.080937-03:00','2023-08-29 13:15:25.080937-03:00',23,'1.8.0-dev-unk');
			CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" varchar(255) );
			CREATE TABLE IF NOT EXISTS "federated_trust_domains" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"trust_domain" varchar(255) NOT NULL,"bundle_endpoint_url" varchar(255),"bundle_endpoint_profile" varchar(255),"endpoint_spiffe_id" varchar(255),"implicit" bool );
			CREATE TABLE IF NOT EXISTS "ca_journals" ("id" integer primary key autoincrement,"created_at" datetime,"updated_at" datetime,"data" blob,"active_x509_authority_id" varchar(255),"active_jwt_authority_id" varchar(255) );
			DELETE FROM sqlite_sequence;
			INSERT INTO sqlite_sequence VALUES('migrations',1);
			INSERT INTO sqlite_sequence VALUES('bundles',1);
			CREATE UNIQUE INDEX uix_bundles_trust_domain ON "bundles"(trust_domain) ;
			CREATE INDEX idx_attested_node_entries_expires_at ON "attested_node_entries"(expires_at) ;
			CREATE UNIQUE INDEX uix_attested_node_entries_spiffe_id ON "attested_node_entries"(spiffe_id) ;
			CREATE UNIQUE INDEX idx_node_resolver_map ON "node_resolver_map_entries"(spiffe_id, "type", "value") ;
			CREATE INDEX idx_registered_entries_spiffe_id ON "registered_entries"(spiffe_id) ;
			CREATE INDEX idx_registered_entries_parent_id ON "registered_entries"(parent_id) ;
			CREATE INDEX idx_registered_entries_expiry ON "registered_entries"("expiry") ;
			CREATE INDEX idx_registered_entries_hint ON "registered_entries"("hint") ;
			CREATE UNIQUE INDEX uix_registered_entries_entry_id ON "registered_entries"(entry_id) ;
			CREATE UNIQUE INDEX uix_join_tokens_token ON "join_tokens"("token") ;
			CREATE INDEX idx_selectors_type_value ON "selectors"("type", "value") ;
			CREATE UNIQUE INDEX idx_selector_entry ON "selectors"(registered_entry_id, "type", "value") ;
			CREATE UNIQUE INDEX idx_dns_entry ON "dns_names"(registered_entry_id, "value") ;
			CREATE UNIQUE INDEX uix_federated_trust_domains_trust_domain ON "federated_trust_domains"(trust_domain) ;
			CREATE INDEX idx_ca_journals_active_x509_authority_id ON "ca_journals"(active_x509_authority_id) ;
			CREATE INDEX idx_ca_journals_active_jwt_authority_id ON "ca_journals"(active_jwt_authority_id) ;
			CREATE INDEX idx_federated_registration_entries_registered_entry_id ON "federated_registration_entries"(registered_entry_id) ;
			COMMIT;
			`,
		24: `
			PRAGMA foreign_keys=OFF;
			BEGIN TRANSACTION;
			CREATE TABLE IF NOT EXISTS "bundles" ("id" integer,"created_at" datetime,"updated_at" datetime,"trust_domain" text NOT NULL,"data" blob,PRIMARY KEY ("id"));
			INSERT INTO bundles VALUES(1,'2023-12-29 13:43:44.885176-03:00','2023-12-29 13:43:44.917521-03:00','spiffe://example.org',X'0a147370696666653a2f2f6578616d706c652e6f726712df030adc03308201d83082015ea0030201020214449db4c88cda977653f4d5e4770aec9b4b1e970c300a06082a8648ce3d040304301e310b3009060355040613025553310f300d060355040a0c06535049464645301e170d3233303531353032303530365a170d3238303531333032303530365a301e310b3009060355040613025553310f300d060355040a0c065350494646453076301006072a8648ce3d020106052b8104002203620004f57073b72f16fdec785ebd117735018227bfa2475a51385e485d0f42f540693b1768fd49ef2bf40e195ac38e48ec2bfd1cfdb51ce98cc48959d177aab0e97db0ce47e7b1c1416bb46c83577f0e2375e1dd079be4d57c8dc81410c5e5294b1867a35d305b301d0603551d0e04160414928ae360c6aaa7cf6aff8d1716b0046aa61c10ff300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630190603551d1104123010860e7370696666653a2f2f6c6f63616c300a06082a8648ce3d0403040368003065023100e7843c85f844778a95c9cc1b2cdcce9bf1d0ae9d67d7e6b6c5cf3c894d37e8530f6a7711d4f2ea82c3833df5b2b6d75102300a2287548b879888c6bdf88dab55b8fc80ec490059f484b2c4177403997b463e9011b3da82f8a6e29254eee45a6293641a85010a5b3059301306072a8648ce3d020106082a8648ce3d03010703420004df6f1f45438786cd90d36b5ef941c20f8d7ef816cd7c6ffecaa7b47a44c83a78ca2dc4b7b3b97ede334b7cde41dffb6d4c104e413a1f7206c6c5c4e93468098a12206757686537564f6b7a414935744944327164514b315057774d6271745736435718c091c1ac062801');
			CREATE TABLE IF NOT EXISTS "registered_entries" ("id" integer,"created_at" datetime,"updated_at" datetime,"entry_id" text,"spiffe_id" text,"parent_id" text,"ttl" integer,"admin" numeric,"downstream" numeric,"expiry" integer,"revision_number" integer,"store_svid" numeric,"hint" text,"jwt_svid_ttl" integer,PRIMARY KEY ("id"));
			CREATE TABLE IF NOT EXISTS "federated_registration_entries" ("registered_entry_id" integer,"bundle_id" integer,PRIMARY KEY ("registered_entry_id","bundle_id"),CONSTRAINT "fk_federated_registration_entries_bundle" FOREIGN KEY ("bundle_id") REFERENCES "bundles"("id"),CONSTRAINT "fk_federated_registration_entries_registered_entry" FOREIGN KEY ("registered_entry_id") REFERENCES "registered_entries"("id"));
			CREATE TABLE IF NOT EXISTS "attested_node_entries" ("id" integer,"created_at" datetime,"updated_at" datetime,"spiffe_id" text,"data_type" text,"serial_number" text,"expires_at" datetime,"new_serial_number" text,"new_expires_at" datetime,"can_reattest" numeric,PRIMARY KEY ("id"));
			CREATE TABLE IF NOT EXISTS "attested_node_entries_events" ("id" integer,"created_at" datetime,"updated_at" datetime,"spiffe_id" text,PRIMARY KEY ("id"));
			CREATE TABLE IF NOT EXISTS "node_resolver_map_entries" ("id" integer,"created_at" datetime,"updated_at" datetime,"spiffe_id" text,"type" text,"value" text,PRIMARY KEY ("id"));
			CREATE TABLE IF NOT EXISTS "registered_entries_events" ("id" integer,"created_at" datetime,"updated_at" datetime,"entry_id" text,PRIMARY KEY ("id"));
			CREATE TABLE IF NOT EXISTS "join_tokens" ("id" integer,"created_at" datetime,"updated_at" datetime,"token" text,"expiry" integer,PRIMARY KEY ("id"));
			CREATE TABLE IF NOT EXISTS "selectors" ("id" integer,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"type" text,"value" text,PRIMARY KEY ("id"),CONSTRAINT "fk_registered_entries_selectors" FOREIGN KEY ("registered_entry_id") REFERENCES "registered_entries"("id"));
			CREATE TABLE IF NOT EXISTS "migrations" ("id" integer,"created_at" datetime,"updated_at" datetime,"version" integer,"code_version" text,PRIMARY KEY ("id"));
			INSERT INTO migrations VALUES(1,'2023-12-29 13:43:44.874425-03:00','2023-12-29 13:43:44.874425-03:00',24,'1.9.0-dev-unk');
			CREATE TABLE IF NOT EXISTS "dns_names" ("id" integer,"created_at" datetime,"updated_at" datetime,"registered_entry_id" integer,"value" text,PRIMARY KEY ("id"),CONSTRAINT "fk_registered_entries_dns_list" FOREIGN KEY ("registered_entry_id") REFERENCES "registered_entries"("id"));
			CREATE TABLE IF NOT EXISTS "federated_trust_domains" ("id" integer,"created_at" datetime,"updated_at" datetime,"trust_domain" text NOT NULL,"bundle_endpoint_url" text,"bundle_endpoint_profile" text,"endpoint_spiffe_id" text,"implicit" numeric,PRIMARY KEY ("id"));
			CREATE TABLE IF NOT EXISTS "ca_journals" ("id" integer,"created_at" datetime,"updated_at" datetime,"data" blob,"active_x509_authority_id" text,"active_jwt_authority_id" text,PRIMARY KEY ("id"));
			CREATE UNIQUE INDEX "idx_bundles_trust_domain" ON "bundles"("trust_domain");
			CREATE INDEX "idx_registered_entries_spiffe_id" ON "registered_entries"("spiffe_id");
			CREATE UNIQUE INDEX "idx_registered_entries_entry_id" ON "registered_entries"("entry_id");
			CREATE INDEX "idx_registered_entries_hint" ON "registered_entries"("hint");
			CREATE INDEX "idx_registered_entries_expiry" ON "registered_entries"("expiry");
			CREATE INDEX "idx_registered_entries_parent_id" ON "registered_entries"("parent_id");
			CREATE INDEX "idx_attested_node_entries_expires_at" ON "attested_node_entries"("expires_at");
			CREATE UNIQUE INDEX "idx_attested_node_entries_spiffe_id" ON "attested_node_entries"("spiffe_id");
			CREATE UNIQUE INDEX "idx_node_resolver_map" ON "node_resolver_map_entries"("spiffe_id","type","value");
			CREATE UNIQUE INDEX "idx_join_tokens_token" ON "join_tokens"("token");
			CREATE INDEX "idx_selectors_type_value" ON "selectors"("type","value");
			CREATE UNIQUE INDEX "idx_selector_entry" ON "selectors"("registered_entry_id","type","value");
			CREATE UNIQUE INDEX "idx_dns_entry" ON "dns_names"("registered_entry_id","value");
			CREATE UNIQUE INDEX "idx_federated_trust_domains_trust_domain" ON "federated_trust_domains"("trust_domain");
			CREATE INDEX "idx_ca_journals_active_jwt_authority_id" ON "ca_journals"("active_jwt_authority_id");
			CREATE INDEX "idx_ca_journals_active_x509_authority_id" ON "ca_journals"("active_x509_authority_id");
			CREATE INDEX "idx_federated_registration_entries_registered_entry_id" ON "federated_registration_entries"("registered_entry_id");
			COMMIT;
		`,
	}
)

func dumpDB(t *testing.T, path string, statements string) {
	db, err := sql.Open("sqlite3", path)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, db.Close())
	}()
	_, err = db.Exec(statements)
	require.NoError(t, err)
}

func TestGetDBCodeVersion(t *testing.T) {
	tests := []struct {
		desc            string
		storedMigration Migration
		expectVersion   semver.Version
		expectErr       string
	}{
		{
			desc:            "no code version",
			storedMigration: Migration{},
			expectVersion:   semver.Version{},
		},
		{
			desc:            "code version, valid",
			storedMigration: Migration{CodeVersion: "1.2.3"},
			expectVersion:   semver.Version{Major: 1, Minor: 2, Patch: 3, Pre: nil, Build: nil},
		},
		{
			desc:            "code version, invalid",
			storedMigration: Migration{CodeVersion: "a.2*.3"},
			expectErr:       "unable to parse code version from DB: Invalid character(s) found in major number \"a\"",
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			retVersion, err := getDBCodeVersion(tt.storedMigration)

			if tt.expectErr != "" {
				assert.Equal(t, semver.Version{}, retVersion)
				assert.Equal(t, tt.expectErr, err.Error())
				return
			}

			assert.Equal(t, tt.expectVersion, retVersion)
			assert.NoError(t, err)
		})
	}
}

func TestIsCompatibleCodeVersion(t *testing.T) {
	tests := []struct {
		desc             string
		thisCodeVersion  semver.Version
		dbCodeVersion    semver.Version
		expectCompatible bool
	}{
		{
			desc:             "backwards compatible 1 minor version",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor - 1)},
			expectCompatible: true,
		},
		{
			desc:             "forwards compatible 1 minor version",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 1)},
			expectCompatible: true,
		},
		{
			desc:             "compatible with self",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    codeVersion,
			expectCompatible: true,
		},
		{
			desc:             "not backwards compatible 2 minor versions",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor - 2)},
			expectCompatible: false,
		},
		{
			desc:             "not forwards compatible 2 minor versions",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 2)},
			expectCompatible: false,
		},
		{
			desc:             "not compatible with different major version but same minor",
			thisCodeVersion:  codeVersion,
			dbCodeVersion:    semver.Version{Major: (codeVersion.Major + 1), Minor: codeVersion.Minor},
			expectCompatible: false,
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			compatible := isCompatibleCodeVersion(tt.thisCodeVersion, tt.dbCodeVersion)

			assert.Equal(t, tt.expectCompatible, compatible)
		})
	}
}

func TestIsDisabledMigrationAllowed(t *testing.T) {
	tests := []struct {
		desc          string
		dbCodeVersion semver.Version
		expectErr     string
	}{
		{
			desc:          "allowed",
			dbCodeVersion: semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 1)},
		},
		{
			desc:          "not allowed, versioning",
			dbCodeVersion: semver.Version{Major: codeVersion.Major, Minor: (codeVersion.Minor + 2)},
			expectErr:     "auto-migration must be enabled for current DB",
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		t.Run(tt.desc, func(t *testing.T) {
			err := isDisabledMigrationAllowed(codeVersion, tt.dbCodeVersion)

			if tt.expectErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.expectErr, err.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}
