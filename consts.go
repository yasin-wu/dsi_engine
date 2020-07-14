package dlp

const (
	RuleTypeKeyWords   = 1
	RuleTypeFuzzyWords = 2
	RuleTypeRegexp     = 3
)

const (
	RuleAnd = 0
	RuleOr  = 1
)

const (
	GRuleMatchFuncName    = "FileGRule.DoMatch"
	GRuleCallbackFuncName = "FileGRule.HandleResult"
)

const (
	DefaultSnapLength   = 100
	DefaultAttachLength = 1000
)

const (
	InfoTypeID       = 1000
	CustomInfoTypeID = 2000
)

var InfoTypeMaps = map[string]string{
	"SECRET_DOCUMENT":          SecretDocumentReg,
	"ORGANIZATION_CODE":        OrgCodeReg,
	"EMAIL":                    EmailReg,
	"IDENTITY_CARD":            IDCardReg,
	"PHONE_NUMBER":             TelNumReg,
	"QQ_NUMBER":                QQReg,
	"POSTAL_CODE":              PostalCodeReg,
	"IPV4":                     IPV4Reg,
	"TAXPAYER_IDENTITY_NUMBER": TaxpayerIdentityNumReg,
	"BANK_CARD":                BankCardNumReg,
	"PASS_PORT":                PassPortReg,
	"ADDRESS":                  AddressReg,
	"ISSUED_NUMBER":            IssuedNumReg,
	"URL":                      URLReg,
	"TAX_NUMBER":               TaxNumReg,
	"BUSINESS_LICENSE":         BusinessLicenseReg,
	"MAC":                      MACReg,
	"IPV6":                     IPV6Reg,
}

const (
	SecretDocumentReg      = "^\\s*?(机密|绝密|秘密|商密一级|商密二级|商密三级)(\\s|☆|★|3年|3个月|6个月|1年|2年|5年|10年|15年|长期|公布前|实施前|实施后2年)*?(\\r|\\n)+?"
	OrgCodeReg             = "([0-9ABCDEFGHJKLMNPQRTUWXY]{2})(\\d{6})([0-9ABCDEFGHJKLMNPQRTUWXY]{9})([0-9ABCDEFGHJKLMNPQRTUWXY])|([a-zA-Z0-9]{8}-[a-zA-Z0-9])"
	EmailReg               = "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b|\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}\\b"
	IDCardReg              = "[1-9]\\d{7}((0\\d)|(1[0-2]))(([0|1|2]\\d)|3[0-1])\\d{3}|[1-9]\\d{5}[1-9]\\d{3}((0\\d)|(1[0-2]))(([0|1|2]\\d)|3[0-1])\\d{3}([0-9]|X)"
	TelNumReg              = "((\\d{11})|((\\d{7,8})|(\\d{4}|\\d{3})-(\\d{7,8})|(\\d{4}|\\d{3})-(\\d{7,8})-(\\d{4}|\\d{3}|\\d{2}|\\d{1})|(\\d{7,8})-(\\d{4}|\\d{3}|\\d{2}|\\d{1})))"
	QQReg                  = "[1-9][0-9]{4,}"
	PostalCodeReg          = "[1-9]\\d{5}"
	IPV4Reg                = "((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}\\b"
	IPV6Reg                = "([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7})\\b"
	TaxpayerIdentityNumReg = "[0-9A-HJ-NPQRTUWXY]{2}\\d{6}[0-9A-HJ-NPQRTUWXY]{10}"
	BankCardNumReg         = "([1-9]{1})(\\d{14}|\\d{18})"
	PassPortReg            = "(P\\d{7}|G\\d{7,8}|TH\\d{7,8}|S\\d{7,8}|A\\d{7,8}|L\\d{7,8}|\\d{9}|D\\d+|1[4,5]\\d{7})"
	AddressReg             = "[\u4E00-\u9FA5]{2,}(省|市|自治区|自治州)([\u4E00-\u9FA5\\w]{1,}(市|区|县|州|道|路|村|组|街|园|号|室|楼)){3,}"
	URLReg                 = "\\b(https|http)://[\\w]+\\.+[\\w]+\\b"
	IssuedNumReg           = "[\u4e00-\u9FA5]{0,20}?[(\\[〔](19[0-9]{2}|20[0-9]{2})[)\\]〕]第?[1-9]\\d*号"
	TaxNumReg              = "\\d{15}"
	BusinessLicenseReg     = "[IOZSV][\\dA-Z]{2}\\d{6}[IOZSV][\\dA-Z]{10}|\\d{15}"
	MACReg                 = "\\b([0-9a-fA-F]{2})(([0-9a-fA-F]{2}){5})\\b|\\b([0-9a-fA-F]{2})(([/\\s:-][0-9a-fA-F]{2}){5})\\b"
)
