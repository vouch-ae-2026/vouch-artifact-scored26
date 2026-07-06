#!/usr/bin/env python3
import json
import os
import sys

import numpy as np
from openfisca_core import entities, periods, variables
from openfisca_core.simulation_builder import SimulationBuilder
from openfisca_core.taxbenefitsystems import TaxBenefitSystem


def load_params():
    path = os.environ.get("VOUCH_OPENFISCA_PARAMS")
    if not path:
        raise RuntimeError("VOUCH_OPENFISCA_PARAMS is required")
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


PARAMS = load_params()
PERSON = entities.build_entity("person", "persons", "Person", is_person=True)
YEAR = periods.YEAR


class annual_income(variables.Variable):
    value_type = int
    entity = PERSON
    definition_period = YEAR
    label = "Annual income"


class household_size(variables.Variable):
    value_type = int
    entity = PERSON
    definition_period = YEAR
    label = "Household size"


class has_disability(variables.Variable):
    value_type = bool
    entity = PERSON
    definition_period = YEAR
    label = "Disability flag"


class is_senior(variables.Variable):
    value_type = bool
    entity = PERSON
    definition_period = YEAR
    label = "Senior flag"


class benefit_amount(variables.Variable):
    value_type = int
    entity = PERSON
    definition_period = YEAR
    label = "Toy benefit amount"

    def formula(person, period):
        income = person("annual_income", period)
        size = person("household_size", period)
        disability = person("has_disability", period)
        senior = person("is_senior", period)
        invalid = (income < 0) | (size < 1)
        base = (
            PARAMS["base"]
            + size * PARAMS["per_person"]
            + disability * PARAMS["disability_bonus"]
            + senior * PARAMS["senior_bonus"]
        )
        band1 = (
            np.minimum(
                np.maximum(income - PARAMS["threshold_1"], 0),
                PARAMS["width_1"],
            )
            // PARAMS["divisor_1"]
        )
        band2 = np.maximum(income - PARAMS["threshold_2"], 0) // PARAMS[
            "divisor_2"
        ]
        raw = base - band1 - band2
        return np.where(invalid, 0, np.maximum(raw, 0))


class benefit_status_code(variables.Variable):
    value_type = int
    entity = PERSON
    definition_period = YEAR
    label = "Toy benefit status code"

    def formula(person, period):
        income = person("annual_income", period)
        size = person("household_size", period)
        amount = person("benefit_amount", period)
        invalid = (income < 0) | (size < 1)
        return np.where(invalid, 2, np.where(amount > 0, 1, 0))


def build_system():
    system = TaxBenefitSystem([PERSON])
    system.add_variables(
        annual_income,
        household_size,
        has_disability,
        is_senior,
        benefit_amount,
        benefit_status_code,
    )
    return system


def evaluate(payload):
    period = payload["period"]
    situation = {"persons": {}}
    for index, case in enumerate(payload["cases"]):
        situation["persons"][f"p{index}"] = {
            "annual_income": {period: case["annual_income"]},
            "household_size": {period: case["household_size"]},
            "has_disability": {period: case["has_disability"]},
            "is_senior": {period: case["is_senior"]},
        }
    simulation = SimulationBuilder().build_from_dict(build_system(), situation)
    amounts = simulation.calculate("benefit_amount", period).tolist()
    statuses = simulation.calculate("benefit_status_code", period).tolist()
    return {
        "runtime": {
            "package": "openfisca-core",
            "version": "44.7.0",
            "period": period,
        },
        "results": [
            {
                "case_id": case["case_id"],
                "benefit_amount": int(amounts[index]),
                "benefit_status_code": int(statuses[index]),
            }
            for index, case in enumerate(payload["cases"])
        ],
    }


def main():
    payload = json.load(sys.stdin)
    json.dump(evaluate(payload), sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
