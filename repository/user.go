package repository

import (
	"context"
	"golang-api/models"

	"go.mongodb.org/mongo-driver/mongo"
)

type UserRepo struct {
	MongoCollection *mongo.Collection
}

func (r *UserRepo) CreateUser(user models.Users) (interface{}, error) {
	result, err := r.MongoCollection.InsertOne(context.Background(), user)
	if err != nil {
		return nil, err
	}

	return result, nil
}
