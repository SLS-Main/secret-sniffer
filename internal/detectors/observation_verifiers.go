package detectors

import (
	"encoding/json"
	"math"
	"strconv"
)

func observationNumbers(p identityPayload, fields ...string) bool {
	if identityHasErrors(p) {
		return false
	}
	for _, field := range fields {
		var number *float64
		if json.Unmarshal(p[field], &number) != nil || number == nil {
			return false
		}
	}
	return true
}

func validTypeformWorkspaces(p identityPayload) bool {
	_, hasCode := p["code"]
	return !hasCode && identityNonnegativeIntegers(p, "total_items", "page_count") && validIdentityCollection(p, "items", func(item identityPayload) bool {
		return !identityHasErrors(item) && identityStrings(item, "id", "name")
	})
}

func validBitGoUser(p identityPayload) bool {
	user := identityObject(p, "user")
	// Frozen or inactive accounts can still have authentic credentials.
	return !identityHasErrors(user) && identityStrings(user, "id", "username")
}

func validFlutterwaveBalances(p identityPayload) bool {
	return identityStringEquals(p, "status", "success") && validIdentityCollection(p, "data", func(balance identityPayload) bool {
		return identityStrings(balance, "currency") && observationNumbers(balance, "available_balance", "ledger_balance")
	})
}

func validOpenWeatherCurrent(p identityPayload) bool {
	var code *int
	return json.Unmarshal(p["cod"], &code) == nil && code != nil && *code == 200 && identityNonnegativeIntegers(p, "dt") &&
		observationNumbers(identityObject(p, "coord"), "lat", "lon") && observationNumbers(identityObject(p, "main"), "temp") &&
		validIdentityCollection(p, "weather", func(weather identityPayload) bool {
			return !identityHasErrors(weather) && identityNonnegativeIntegers(weather, "id") && identityStrings(weather, "main")
		})
}

func validTomorrowCurrent(p identityPayload) bool {
	_, hasCode := p["code"]
	data := identityObject(p, "data")
	return !hasCode && !identityHasErrors(data) && identityStrings(data, "time") && observationNumbers(identityObject(data, "values"), "temperature") && observationNumbers(identityObject(p, "location"), "lat", "lon")
}

func validHEREGeocode(p identityPayload) bool {
	_, hasStatus := p["status"]
	_, hasCode := p["errorCode"]
	return !hasStatus && !hasCode && validIdentityCollection(p, "items", func(item identityPayload) bool {
		return !identityHasErrors(item) && identityStrings(item, "id", "title", "resultType") && observationNumbers(identityObject(item, "position"), "lat", "lng")
	})
}

func validWorldWeatherCurrent(p identityPayload) bool {
	data := identityObject(p, "data")
	var current []json.RawMessage
	if identityHasErrors(data) || json.Unmarshal(data["current_condition"], &current) != nil || len(current) == 0 {
		return false
	}
	return validIdentityCollection(data, "request", func(request identityPayload) bool {
		return !identityHasErrors(request) && identityStrings(request, "type", "query")
	}) && validIdentityCollection(data, "current_condition", func(condition identityPayload) bool {
		var temp string
		if identityHasErrors(condition) || !identityStrings(condition, "observation_time", "weatherCode") || json.Unmarshal(condition["temp_C"], &temp) != nil {
			return false
		}
		value, err := strconv.ParseFloat(temp, 64)
		return err == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
	})
}
