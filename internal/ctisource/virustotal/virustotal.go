package virustotal

type Source struct{}

func NewSource() *Source {
	return &Source{}
}

func (s *Source) Name() string {
	return "virustotal"
}
