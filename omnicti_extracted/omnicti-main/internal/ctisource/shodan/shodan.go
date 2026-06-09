package shodan

type Source struct{}

func NewSource() *Source {
	return &Source{}
}

func (s *Source) Name() string {
	return "shodan"
}
