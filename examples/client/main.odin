package client_example

import "core:fmt"

import "../../client"

main :: proc() {
	get()
	post()
}

// basic get request.
get :: proc() {
	res, err := client.get("https://www.google.com/")
	if err != nil {
		fmt.printf("Request failed: %v\n", err)
		return
	}
	defer client.response_destroy(&res)

	fmt.printf("Status: %v\n", res.status)
	fmt.printf("Headers: %v\n", res.headers)
	fmt.printf("Cookies: %v\n", res.cookies)
	fmt.println(res.body)
}

Post_Body :: struct {
	name:    string,
	message: string,
}

// POST request with JSON.
post :: proc() {
	req: client.Request
	client.request_init(&req, .Post)
	defer client.request_destroy(&req)

	pbody := Post_Body{"Laytan", "Hello, World!"}
	if err := client.with_json(&req, pbody); err != nil {
		fmt.printf("JSON error: %v\n", err)
		return
	}

	res, err := client.request(&req, "https://webhook.site/YOUR-ID-HERE")
	if err != nil {
		fmt.printf("Request failed: %v\n", err)
		return
	}
	defer client.response_destroy(&res)

	fmt.printf("Status: %v\n", res.status)
	fmt.printf("Headers: %v\n", res.headers)
	fmt.printf("Cookies: %v\n", res.cookies)
	fmt.println(res.body)
}
