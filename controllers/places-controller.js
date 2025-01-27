const mongoose = require("mongoose");
const fs = require("fs");
const HttpError = require("../models/http-error");
const { validationResult } = require("express-validator");
const { getCoordsForAddress } = require("../util/location");
const Place = require("../models/place");
const User = require("../models/user");

exports.getPlaceById = async (req, res, next) => {
  const placeId = req.params.pid;
  let place;
  try {
    place = await Place.findById(placeId);
  } catch (err) {
    const error = new HttpError("Something went wrong. Please try again.", 500);
    return next(error);
  }

  if (!place) {
    return next(new HttpError("Place not found.", 404));
  }

  res.json({
    place: place.toObject({ getters: true }),
  });
};

exports.getPlacesByUserId = async (req, res, next) => {
  const userId = req.params.uid;

  let userWithPlaces;
  try {
    userWithPlaces = await User.findById(userId).populate("places");
  } catch (error) {
    return next(
      new HttpError("Fetching places failed. Please try again.", 500)
    );
  }

  if (!userWithPlaces || userWithPlaces.places.length === 0) {
    return next(new HttpError("Place not found for given user id.", 404));
  }

  res.json({
    places: userWithPlaces.places.map((place) =>
      place.toObject({ getters: true })
    ),
  });
};

exports.createPlace = async (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return next(new HttpError("Invalid inputs passed.", 422));
  }

  const { title, description, address } = req.body;

  let coordinates;

  try {
    coordinates = await getCoordsForAddress(address);
  } catch (error) {
    return next(error);
  }

  const createdPlace = new Place({
    title,
    description,
    image: req.file.path,
    address,
    location: coordinates,
    creator: req.userData.userId,
  });

  let user;

  try {
    user = await User.findById(req.userData.userId);
  } catch (error) {
    return next(new HttpError("Creating place failed. Please try again.", 500));
  }

  if (!user) {
    return next(
      new HttpError("User not found for provided id. Please try again.", 404)
    );
  }

  try {
    const sess = await mongoose.startSession();
    sess.startTransaction();
    await createdPlace.save({ session: sess });
    user.places.push(createdPlace);
    await user.save({ session: sess });
    await sess.commitTransaction();
  } catch (err) {
    return next(new HttpError("Creating place failed. Please try again.", 500));
  }

  res.status(201).json({ message: "Place Created", place: createdPlace });
};

exports.updatePlace = async (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return next(new HttpError("Invalid inputs passed.", 422));
  }

  const { title, description } = req.body;
  const placeId = req.params.pid;

  let place;

  try {
    place = await Place.findById(placeId);
  } catch (error) {
    return next(new HttpError("Something went wrong. Please try again.", 500));
  }

  if (place.creator.toString() !== req.userData.userId) {
    return next(
      new HttpError("You are not authorized to edit this place.", 401)
    );
  }

  place.title = title;
  place.description = description;

  try {
    await place.save();
  } catch (error) {
    return next(new HttpError("Something went wrong. Please try again.", 500));
  }

  res.status(200).json({
    message: "Place Updated.",
    place: place.toObject({ getters: true }),
  });
};

exports.deletePlace = async (req, res, next) => {
  const placeId = req.params.pid;
  let place;
  try {
    place = await Place.findById(placeId).populate("creator");
  } catch (error) {
    return next(new HttpError("Something went wrong. Please try again.", 500));
  }

  if (!place) {
    return next(new HttpError("Place not found for given id.", 404));
  }

  if (place.creator.id !== req.userData.userId) {
    return next(
      new HttpError("You are not authorized to delete this place.", 401)
    );
  }

  const imagePath = place.image;

  try {
    const sess = await mongoose.startSession();
    sess.startTransaction();
    await place.deleteOne({ session: sess });
    place.creator.places.pull(place);
    await place.creator.save({ session: sess });
    await sess.commitTransaction();
  } catch (error) {
    return next(new HttpError("Something went wrong. Please try again2.", 500));
  }

  fs.unlink(imagePath, (err) => console.log(err));

  res.status(200).json({ message: "Place Deleted." });
};
