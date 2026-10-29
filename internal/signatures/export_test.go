package signatures

func NegatedRansomwarePaymentForTest(data []byte, at int) bool {
	return negatedRansomwarePayment(data, at)
}

func AcceptRansomwareInstanceForTest(identifier string, data []byte, start, end int) bool {
	return acceptRansomwareInstance(identifier, data, start, end)
}

func LongBase64SpansForTest(data []byte) []Span {
	return longBase64Spans(data)
}
