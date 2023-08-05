# go-verifyotp



```

...

import (
  "context"
  verify "github.com/verifyotp/go-verifyotp"
)

func VerifyUser(phoneNo string) error {

  client, err := verify.New()
  if err != nil {
    return err
  }

  _, err = client.SendOTP(context.Background(), verify.VerifyotpSendOTPRequest{
      Recipient: "+234940304500",
      Channel: "sms",
    }
  if err != nil {
    return err
  }

  return nil  
}

```
