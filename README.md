func:infotypelist
output json:
    "data": [
        "IPV4",
        "BANK_CARD",
        "URL",
        "BUSINESS_LICENSE",
        "POSTAL_CODE",
        "IPV6",
        "EMAIL",
        "IDENTITY_CARD",
        "PHONE_NUMBER",
        "QQ_NUMBER",
        "TAXPAYER_IDENTITY_NUMBER",
        "PASS_PORT",
        "ADDRESS",
        "TAX_NUMBER",
        "ORGANIZATION_CODE",
        "ISSUED_NUMBER",
        "MAC",
        "SECRET_DOCUMENT"
    ]

func:inspect
input json:
    {
        "item": {
            "id": "1592460121197",
            "value": "My phone number is (415) 555-0890"
        },
        "inspectConfig": {
            "infoTypes": [
                {
                    "name": "PHONE_NUMBER"
                }
            ],
            "customInfoTypes": [
                {
                    "infoType": {
                        "name": "C_MRN"
                    },
                    "regex": {
                        "pattern": "[1-9]{3}-[1-9]{1}-[1-9]{5}"
                    }
                }
            ]
        }
    }
output json:
    {
        "findings": [
            {
                "quote": "(415) 555-0890",
                "infoType": {
                    "name": "PHONE_NUMBER"
                },
                "location": {
                    "byteRange": {
                        "start": 19,
                        "end": 33
                    }
                },
                "createTime": "2018-11-13T19:29:15.412Z"
            }
        ]
    }