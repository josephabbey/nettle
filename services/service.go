package services

import "context"

type Service interface {
	Start(context.Context) error
	Stop(context.Context) error
}
