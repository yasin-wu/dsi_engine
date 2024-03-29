package rule

// nolint:lll
var defaultRule = `{
  "SECRET_DOCUMENT": {
    "desc": "绝密文件",
    "regexp": "^\\s*?(机密|绝密|秘密|商密一级|商密二级|商密三级)(\\s|☆|★|3年|3个月|6个月|1年|2年|5年|10年|15年|长期|公布前|实施前|实施后2年)*?(\\r|\\n)+?"
  },
  "ORGANIZATION_CODE": {
    "desc": "组织机构编码",
    "regexp": "([0-9ABCDEFGHJKLMNPQRTUWXY]{2})(\\d{6})([0-9ABCDEFGHJKLMNPQRTUWXY]{9})([0-9ABCDEFGHJKLMNPQRTUWXY])|([a-zA-Z0-9]{8}-[a-zA-Z0-9])"
  },
  "EMAIL": {
    "desc": "电子邮箱",
    "regexp": "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b|\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}\\b"
  },
  "IDENTITY_CARD": {
    "desc": "身份证",
    "regexp": "[1-9]\\d{7}((0\\d)|(1[0-2]))(([0|1|2]\\d)|3[0-1])\\d{3}|[1-9]\\d{5}[1-9]\\d{3}((0\\d)|(1[0-2]))(([0|1|2]\\d)|3[0-1])\\d{3}([0-9]|X)"
  },
  "PHONE_NUMBER": {
    "desc": "电话号码",
    "regexp": "((\\d{11})|((\\d{7,8})|(\\d{4}|\\d{3})-(\\d{7,8})|(\\d{4}|\\d{3})-(\\d{7,8})-(\\d{4}|\\d{3}|\\d{2}|\\d{1})|(\\d{7,8})-(\\d{4}|\\d{3}|\\d{2}|\\d{1})))"
  },
  "QQ": {
    "desc": "腾讯QQ号",
    "regexp": "[1-9][0-9]{4,}"
  },
  "POSTAL_CODE": {
    "desc": "邮政编码",
    "regexp": "[1-9]\\d{5}"
  },
  "IPV4": {
    "desc": "ipv4地址",
    "regexp": "((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}\\b"
  },
  "IPV6": {
    "desc": "ipv6地址",
    "regexp": "([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7})\\b"
  },
  "TAXPAYER_IDENTITY_NUMBER": {
    "desc": "纳税人身份识别号",
    "regexp": "[0-9A-HJ-NPQRTUWXY]{2}\\d{6}[0-9A-HJ-NPQRTUWXY]{10}"
  },
  "BANK_CARD": {
    "desc": "银行卡",
    "regexp": "([1-9]{1})(\\d{14}|\\d{18})"
  },
  "PASS_PORT": {
    "desc": "护照",
    "regexp": "(P\\d{7}|G\\d{7,8}|TH\\d{7,8}|S\\d{7,8}|A\\d{7,8}|L\\d{7,8}|\\d{9}|D\\d+|1[4,5]\\d{7})"
  },
  "ADDRESS": {
    "desc": "地址信息",
    "regexp": "[\u4E00-\u9FA5]{2,}(省|市|自治区|自治州)([\u4E00-\u9FA5\\w]{1,}(市|区|县|州|道|路|村|组|街|园|号|室|楼)){3,}"
  },
  "ISSUED_NUMBER": {
    "desc": "发文字号",
    "regexp": "[\u4E00-\u9FA5]{0,20}?[(\\[〔](19[0-9]{2}|20[0-9]{2})[)\\]〕]第?[1-9]\\d*号"
  },
  "URL": {
    "desc": "url地址",
    "regexp": "\\b(https|http)://[\\w]+\\.+[\\w]+\\b"
  },
  "TAXPAYER_NUMBER": {
    "desc": "税务登记号15位",
    "regexp": "\\d{15}"
  },
  "BUSINESS_LICENSE": {
    "desc": "营业执照",
    "regexp": "[IOZSV][\\dA-Z]{2}\\d{6}[IOZSV][\\dA-Z]{10}|\\d{15}"
  },
  "MAC": {
    "desc": "mac地址",
    "regexp": "\\b([0-9a-fA-F]{2})(([0-9a-fA-F]{2}){5})\\b|\\b([0-9a-fA-F]{2})(([/\\s:-][0-9a-fA-F]{2}){5})\\b"
  }
}`
