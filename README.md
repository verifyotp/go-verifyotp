# go-verifyotp



```

...

package main

import (
	"context"
	"fmt"
	verifyotp "github.com/verifyotp/go-verifyotp" // Import the package from your local directory
)

func main() {
	// Initialize the client with the base URL and any options you might need
	client, err := verifyotp.New()
	if err != nil {
		fmt.Println("Error initializing client:", err)
		return
	}

	// Prepare the OTP request parameters
	otpRequest := verifyotp.VerifyotpSendOTPRequest{
		Recipient:   "user@example.com", // Recipient's email or phone number
		Channel:     "email",      // Channel to send OTP (email, SMS, etc.)
	}

	// Send the OTP
	response, err := client.Verifyotp.SendOTP(context.Background(), otpRequest)
	if err != nil {
		fmt.Println("Error sending OTP:", err)
		return
	}

	// Print the response
	fmt.Println("OTP sent successfully!")
	fmt.Printf("Reference: %s\n", response.Data.Reference)
}



```
