package main

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo"
)

var teams = make(map[string]string)

func getTeamData(c echo.Context) error {
	teamName := c.Param("team_name")
	data, ok := teams[teamName]
	if !ok {
		return c.String(http.StatusOK, "team does not exist")
	}

	return c.String(http.StatusOK, data)
}

func setTeamData(c echo.Context) error {
	teamName := c.Param("team_name")
	teams[teamName] = c.FormValue("data")
	fmt.Println("Set Data:", teamName)
	return c.String(http.StatusOK, "successful")
}

func main() {
	e := echo.New()
	e.GET("/:team_name", getTeamData)
	e.POST("/:team_name", setTeamData)
	e.Logger.Fatal(e.Start(":8080"))
}
