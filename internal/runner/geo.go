//i18nkeys:skip — place names are matched against site answers, not shown.

package runner

import "strings"

// The country of the address a local site sees is read from that site's own
// answer, without asking any third party: Yandex names the city (in Russian),
// Bilibili names the country (in Chinese), ifconfig.ir gives an ISO code.
// The tables below are built in once; an unknown name gives "" (no flag),
// and the verdict then relies on comparing the addresses alone.

// ruCities are Russian cities as Yandex names them (regional centres and
// cities above about 100 000 people).
var ruCities = strings.Fields(`
Москва Санкт-Петербург Новосибирск Екатеринбург Казань Нижний_Новгород Челябинск Красноярск Самара
Уфа Ростов-на-Дону Омск Краснодар Воронеж Пермь Волгоград Саратов Тюмень Тольятти Ижевск Барнаул
Ульяновск Иркутск Хабаровск Махачкала Ярославль Владивосток Оренбург Томск Кемерово Новокузнецк
Рязань Набережные_Челны Астрахань Киров Пенза Севастополь Балашиха Липецк Чебоксары Калининград Тула
Ставрополь Курск Улан-Удэ Сочи Тверь Магнитогорск Иваново Брянск Белгород Сургут Владимир Чита
Архангельск Нижний_Тагил Симферополь Калуга Смоленск Волжский Якутск Саранск Череповец Курган
Вологда Орёл Орел Владикавказ Подольск Грозный Мурманск Тамбов Стерлитамак Петрозаводск Кострома
Нижневартовск Новороссийск Йошкар-Ола Химки Таганрог Комсомольск-на-Амуре Сыктывкар Нальчик
Шахты Дзержинск Братск Орск Нижнекамск Ангарск Энгельс Благовещенск Великий_Новгород Старый_Оскол
Псков Королёв Королев Мытищи Люберцы Южно-Сахалинск Бийск Прокопьевск Армавир Балаково Рыбинск
Абакан Северодвинск Петропавловск-Камчатский Норильск Уссурийск Волгодонск Красногорск Сызрань
Новочеркасск Каменск-Уральский Златоуст Электросталь Альметьевск Салават Миасс Керчь Копейск
Находка Пятигорск Хасавюрт Рубцовск Березники Коломна Майкоп Одинцово Ковров Домодедово Нефтекамск
Кисловодск Нефтеюганск Батайск Новочебоксарск Серпухов Щёлково Дербент Новомосковск
Черкесск Первоуральск Раменское Назрань Каспийск Обнинск Орехово-Зуево Кызыл Новый_Уренгой
Невинномысск Октябрьский Димитровград Ессентуки Камышин Евпатория Муром Ноябрьск Сергиев_Посад
Елец Ачинск Арзамас Новошахтинск Элиста Бердск Пушкино Жуковский Магадан Анадырь Салехард
Ханты-Мансийск Горно-Алтайск Биробиджан Нарьян-Мар Зеленоград Ногинск Реутов Видное
`)

// ruRegionWords mark a Russian region name ("Московская область", "Пермский край").
var ruRegionWords = []string{"область", "край", "автономный округ", "Россия"}

// foreignCities are cities and countries Yandex may name for a foreign exit.
var foreignCities = map[string]string{
	"Хельсинки": "FI", "Финляндия": "FI", "Эспоо": "FI", "Таллин": "EE", "Таллинн": "EE", "Эстония": "EE",
	"Рига": "LV", "Латвия": "LV", "Вильнюс": "LT", "Литва": "LT", "Стокгольм": "SE", "Швеция": "SE",
	"Осло": "NO", "Норвегия": "NO", "Копенгаген": "DK", "Дания": "DK", "Амстердам": "NL", "Нидерланды": "NL",
	"Роттердам": "NL", "Франкфурт-на-Майне": "DE", "Франкфурт": "DE", "Берлин": "DE", "Мюнхен": "DE",
	"Гамбург": "DE", "Дюссельдорф": "DE", "Нюрнберг": "DE", "Фалькенштейн": "DE", "Германия": "DE",
	"Лондон": "GB", "Великобритания": "GB", "Париж": "FR", "Франция": "FR", "Брюссель": "BE", "Бельгия": "BE",
	"Цюрих": "CH", "Женева": "CH", "Швейцария": "CH", "Вена": "AT", "Австрия": "AT", "Прага": "CZ", "Чехия": "CZ",
	"Варшава": "PL", "Польша": "PL", "Мадрид": "ES", "Испания": "ES", "Милан": "IT", "Рим": "IT", "Италия": "IT",
	"Дублин": "IE", "Ирландия": "IE", "Лиссабон": "PT", "Португалия": "PT", "Бухарест": "RO", "Румыния": "RO",
	"София": "BG", "Болгария": "BG", "Белград": "RS", "Сербия": "RS", "Будапешт": "HU", "Венгрия": "HU",
	"Кишинёв": "MD", "Кишинев": "MD", "Молдова": "MD", "Стамбул": "TR", "Анкара": "TR", "Турция": "TR",
	"Тбилиси": "GE", "Грузия": "GE", "Ереван": "AM", "Армения": "AM", "Баку": "AZ", "Азербайджан": "AZ",
	"Минск": "BY", "Беларусь": "BY", "Киев": "UA", "Украина": "UA", "Алматы": "KZ", "Астана": "KZ",
	"Казахстан": "KZ", "Ташкент": "UZ", "Узбекистан": "UZ", "Бишкек": "KG", "Киргизия": "KG",
	"Дубай": "AE", "ОАЭ": "AE", "Тель-Авив": "IL", "Израиль": "IL", "Нью-Йорк": "US", "Лос-Анджелес": "US",
	"Майами": "US", "Сан-Франциско": "US", "Сиэтл": "US", "Даллас": "US", "Чикаго": "US", "Эшберн": "US",
	"США": "US", "Торонто": "CA", "Монреаль": "CA", "Канада": "CA", "Сингапур": "SG", "Токио": "JP",
	"Япония": "JP", "Гонконг": "HK", "Сеул": "KR", "Южная Корея": "KR", "Пекин": "CN", "Шанхай": "CN",
	"Китай": "CN", "Сидней": "AU", "Австралия": "AU", "Мумбаи": "IN", "Индия": "IN",
}

// zhCountries are the Chinese country names Bilibili and similar services use.
var zhCountries = map[string]string{
	"中国": "CN", "俄罗斯": "RU", "芬兰": "FI", "荷兰": "NL", "德国": "DE", "美国": "US", "日本": "JP",
	"韩国": "KR", "新加坡": "SG", "英国": "GB", "法国": "FR", "瑞典": "SE", "瑞士": "CH", "加拿大": "CA",
	"澳大利亚": "AU", "印度": "IN", "土耳其": "TR", "阿联酋": "AE", "爱沙尼亚": "EE", "拉脱维亚": "LV",
	"立陶宛": "LT", "波兰": "PL", "奥地利": "AT", "意大利": "IT", "西班牙": "ES", "爱尔兰": "IE",
	"哈萨克斯坦": "KZ", "伊朗": "IR", "越南": "VN", "泰国": "TH", "马来西亚": "MY", "菲律宾": "PH",
	"印度尼西亚": "ID", "中国香港": "HK", "香港": "HK", "中国澳门": "MO", "澳门": "MO", "中国台湾": "TW", "台湾": "TW",
}

var ruCitySet = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range ruCities {
		m[strings.ReplaceAll(c, "_", " ")] = true
	}
	return m
}()

// CountryOfCity maps a region name from Yandex to a country code ("" if unknown).
func CountryOfCity(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if ruCitySet[name] {
		return "RU"
	}
	if c, ok := foreignCities[name]; ok {
		return c
	}
	for _, w := range ruRegionWords {
		if strings.Contains(name, w) {
			return "RU"
		}
	}
	return ""
}

// CountryOfZh maps a Chinese country name to a code; a mainland answer whose
// province is Hong Kong, Macao or Taiwan is reported as that territory.
func CountryOfZh(country, province string) string {
	if country == "中国" {
		if c, ok := zhCountries[province]; ok {
			return c
		}
	}
	return zhCountries[country]
}

// isISOCode reports whether s looks like a two-letter country code ("FI", "ir").
func isISOCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}
