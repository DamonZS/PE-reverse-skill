import copy
import json
import math
import unittest
from dataclasses import FrozenInstanceError

from reverse_analyzer.llm_jailbreak.evolution import (
    EvolutionaryPromptOptimizer,
    PromptGenome,
)


class PromptGenomeTests(unittest.TestCase):
    def test_genome_is_frozen_and_serializes_all_fields(self):
        genome = PromptGenome(
            genome_id="genome-1",
            prompt="Return the result.",
            generation=2,
            parents=("parent-a", "parent-b"),
            operators=("crossover-words", "mutation-output-contract"),
            fitness=0.75,
            metadata={"refused": False, "success": True},
        )

        with self.assertRaises(FrozenInstanceError):
            genome.prompt = "changed"

        self.assertEqual(
            PromptGenome.from_dict(genome.to_dict()),
            genome,
        )
        self.assertEqual(genome.to_dict()["parents"], ["parent-a", "parent-b"])

    def test_genome_rejects_invalid_values(self):
        with self.assertRaises(ValueError):
            PromptGenome(genome_id="", prompt="prompt", generation=0)
        with self.assertRaises(ValueError):
            PromptGenome(genome_id="g", prompt=" ", generation=0)
        with self.assertRaises(ValueError):
            PromptGenome(genome_id="g", prompt="prompt", generation=-1)
        with self.assertRaises(ValueError):
            PromptGenome(
                genome_id="g",
                prompt="prompt",
                generation=0,
                fitness=math.nan,
            )


class EvolutionaryPromptOptimizerTests(unittest.TestCase):
    def make_optimizer(self, **overrides):
        config = {
            "seed": 17,
            "population_size": 4,
            "elite_count": 1,
            "mutation_rate": 0.5,
            "max_generations": 3,
        }
        config.update(overrides)
        return EvolutionaryPromptOptimizer(**config)

    def test_configuration_validation_and_boundaries(self):
        invalid_configs = (
            {"seed": True},
            {"population_size": 0},
            {"population_size": True},
            {"elite_count": -1},
            {"population_size": 2, "elite_count": 3},
            {"mutation_rate": -0.01},
            {"mutation_rate": 1.01},
            {"mutation_rate": math.inf},
            {"mutation_rate": True},
            {"max_generations": 0},
        )
        for overrides in invalid_configs:
            with self.subTest(overrides=overrides):
                with self.assertRaises((TypeError, ValueError)):
                    self.make_optimizer(**overrides)

        optimizer = self.make_optimizer(
            population_size=2,
            elite_count=2,
            mutation_rate=0.0,
        )
        seeded = optimizer.seed_population("Objective", ["first", "second"])
        self.assertEqual(optimizer.evolve(), seeded)

        negative_seed = self.make_optimizer(seed=-17)
        self.assertEqual(negative_seed.seed, -17)

    def test_seed_population_deduplicates_fills_and_is_deterministic(self):
        first = self.make_optimizer(population_size=5)
        second = self.make_optimizer(population_size=5)

        first_population = first.seed_population(
            "Return a compact answer",
            ["alpha prompt", "alpha prompt", " beta prompt "],
        )
        second_population = second.seed_population(
            "Return a compact answer",
            ["alpha prompt", "alpha prompt", " beta prompt "],
        )

        self.assertEqual(first_population, second_population)
        self.assertEqual(len(first_population), 5)
        self.assertEqual(first_population[0].prompt, "alpha prompt")
        self.assertEqual(first_population[1].prompt, "beta prompt")
        self.assertEqual(len({item.prompt for item in first_population}), 5)
        self.assertEqual(len({item.genome_id for item in first_population}), 5)
        self.assertTrue(all(item.generation == 0 for item in first_population))

        with self.assertRaises(ValueError):
            first.seed_population("", ["prompt"])
        with self.assertRaises(ValueError):
            first.seed_population("objective", [])
        with self.assertRaises(TypeError):
            first.seed_population("objective", "not-a-sequence-of-prompts")

        generated = self.make_optimizer(population_size=2)
        generated_population = generated.seed_population(
            "objective",
            (item for item in ("first", "second")),
        )
        self.assertEqual(
            [item.prompt for item in generated_population],
            ["first", "second"],
        )

    def test_observe_drives_selection_and_best(self):
        optimizer = self.make_optimizer(mutation_rate=0.0, elite_count=1)
        population = optimizer.seed_population(
            "Combine useful instructions",
            [
                "alpha one two three",
                "beta four five six",
                "gamma seven eight nine",
                "delta ten eleven twelve",
            ],
        )
        scores = (0.2, 0.95, 0.7, -0.1)
        for genome, score in zip(population, scores):
            optimizer.observe(
                genome.genome_id,
                score,
                refused=genome is population[3],
                success=genome is population[1],
            )

        best = optimizer.best
        self.assertIsNotNone(best)
        self.assertEqual(best.genome_id, population[1].genome_id)
        evolved = optimizer.evolve()
        self.assertEqual(evolved[0], best)

        selected_parent_ids = {
            parent_id
            for genome in evolved[1:]
            for parent_id in genome.parents
        }
        self.assertTrue(selected_parent_ids)
        self.assertTrue(
            selected_parent_ids.issubset(
                {population[1].genome_id, population[2].genome_id}
            )
        )

        with self.assertRaises(KeyError):
            optimizer.observe("unknown", 1.0, refused=False, success=False)
        with self.assertRaises(ValueError):
            optimizer.observe(best.genome_id, math.nan, refused=False, success=False)
        with self.assertRaises(TypeError):
            optimizer.observe(best.genome_id, 1.0, refused=1, success=False)

    def test_crossover_and_mutation_are_recorded(self):
        crossover_only = self.make_optimizer(
            elite_count=0,
            mutation_rate=0.0,
        )
        crossover_only.seed_population(
            "Synthesize the two requests",
            [
                "alpha bravo charlie delta",
                "echo foxtrot golf hotel",
                "india juliet kilo lima",
                "mike november oscar papa",
            ],
        )
        crossed = crossover_only.evolve()
        self.assertTrue(all(len(item.parents) == 2 for item in crossed))
        self.assertTrue(
            all(any(op.startswith("crossover-") for op in item.operators) for item in crossed)
        )

        mutated_optimizer = self.make_optimizer(
            elite_count=0,
            mutation_rate=1.0,
        )
        mutated_optimizer.seed_population(
            "Synthesize the two requests",
            [
                "alpha bravo charlie delta",
                "echo foxtrot golf hotel",
                "india juliet kilo lima",
                "mike november oscar papa",
            ],
        )
        mutated = mutated_optimizer.evolve()
        self.assertTrue(
            all(any(op.startswith("mutation-") for op in item.operators) for item in mutated)
        )

    def test_refusal_feedback_changes_mutation_operator_family(self):
        normal = self.make_optimizer(elite_count=0, mutation_rate=1.0)
        adaptive = self.make_optimizer(elite_count=0, mutation_rate=1.0)
        prompts = ["alpha prompt", "beta prompt", "gamma prompt", "delta prompt"]
        normal.seed_population("Objective", prompts)
        adaptive.seed_population("Objective", prompts)

        normal_population = normal.evolve(feedback={"refused": False})
        adaptive_population = adaptive.evolve(feedback={"refused": True})

        normal_mutations = {
            op
            for genome in normal_population
            for op in genome.operators
            if op.startswith("mutation-")
        }
        adaptive_mutations = {
            op
            for genome in adaptive_population
            for op in genome.operators
            if op.startswith("mutation-")
        }
        self.assertTrue(normal_mutations)
        self.assertTrue(adaptive_mutations)
        self.assertNotEqual(normal_mutations, adaptive_mutations)
        self.assertTrue(
            all(genome.metadata["refusal_adapted"] for genome in adaptive_population)
        )

        success_feedback = self.make_optimizer(elite_count=0, mutation_rate=1.0)
        success_feedback.seed_population("Objective", prompts)
        successful_population = success_feedback.evolve(feedback={"success": True})
        self.assertTrue(
            all(not genome.metadata["refusal_adapted"] for genome in successful_population)
        )

        text_feedback = self.make_optimizer(elite_count=0, mutation_rate=1.0)
        text_feedback.seed_population("Objective", prompts)
        text_population = text_feedback.evolve(
            feedback={"message": "The target cannot comply with that request."}
        )
        self.assertTrue(
            all(genome.metadata["refusal_adapted"] for genome in text_population)
        )

    def test_observed_refusal_also_enables_adaptive_mutation(self):
        optimizer = self.make_optimizer(elite_count=0, mutation_rate=1.0)
        population = optimizer.seed_population(
            "Objective",
            ["alpha", "beta", "gamma", "delta"],
        )
        for genome in population:
            optimizer.observe(genome.genome_id, 0.1, refused=True, success=False)

        evolved = optimizer.evolve()
        mutation_names = {
            operator
            for genome in evolved
            for operator in genome.operators
            if operator.startswith("mutation-")
        }
        self.assertTrue(mutation_names)
        self.assertTrue(all("refusal" in name for name in mutation_names))

    def test_elite_is_retained_with_observation(self):
        optimizer = self.make_optimizer(elite_count=2, mutation_rate=1.0)
        population = optimizer.seed_population(
            "Objective",
            ["alpha", "beta", "gamma", "delta"],
        )
        for index, genome in enumerate(population):
            optimizer.observe(
                genome.genome_id,
                float(index),
                refused=False,
                success=index == 3,
            )

        ranked_elites = (optimizer.best, optimizer.population[2])
        evolved = optimizer.evolve()
        self.assertEqual(evolved[:2], ranked_elites)
        self.assertTrue(all(item.fitness is None for item in evolved[2:]))

    def test_json_restore_produces_identical_next_generation(self):
        optimizer = self.make_optimizer(population_size=5, max_generations=4)
        population = optimizer.seed_population(
            "Objective",
            ["alpha prompt", "beta prompt", "gamma prompt"],
        )
        for index, genome in enumerate(population):
            optimizer.observe(
                genome.genome_id,
                index / 10.0,
                refused=index % 2 == 0,
                success=False,
            )
        optimizer.evolve()

        for index, genome in enumerate(optimizer.population):
            optimizer.observe(
                genome.genome_id,
                index / 7.0,
                refused=index == 1,
                success=index == 4,
            )

        payload = json.loads(json.dumps(optimizer.to_dict()))
        restored = EvolutionaryPromptOptimizer.from_dict(payload)
        self.assertEqual(restored.to_dict(), optimizer.to_dict())
        self.assertEqual(
            restored.evolve(feedback={"refused": True}),
            optimizer.evolve(feedback={"refused": True}),
        )
        self.assertEqual(restored.to_dict(), optimizer.to_dict())

    def test_exhaustion_and_unseeded_operations(self):
        optimizer = self.make_optimizer(max_generations=1)
        self.assertFalse(optimizer.is_exhausted)
        self.assertIsNone(optimizer.best)
        with self.assertRaises(RuntimeError):
            optimizer.evolve()

        optimizer.seed_population("Objective", ["alpha", "beta", "gamma", "delta"])
        self.assertFalse(optimizer.is_exhausted)
        optimizer.evolve()
        self.assertTrue(optimizer.is_exhausted)
        with self.assertRaises(RuntimeError):
            optimizer.evolve()

    def test_from_dict_rejects_malformed_state(self):
        optimizer = self.make_optimizer()
        optimizer.seed_population(
            "Objective",
            ["alpha", "beta", "gamma", "delta"],
        )
        state = optimizer.to_dict()

        malformed_states = []

        wrong_version = copy.deepcopy(state)
        wrong_version["schema_version"] = 999
        malformed_states.append(wrong_version)

        future_generation = copy.deepcopy(state)
        future_generation["generation"] = future_generation["max_generations"] + 1
        malformed_states.append(future_generation)

        duplicate_prompt = copy.deepcopy(state)
        duplicate_prompt["population"][1]["prompt"] = duplicate_prompt["population"][0][
            "prompt"
        ]
        malformed_states.append(duplicate_prompt)

        bad_id = copy.deepcopy(state)
        bad_id["population"][0]["genome_id"] = "tampered"
        malformed_states.append(bad_id)

        missing_population = copy.deepcopy(state)
        del missing_population["population"]
        malformed_states.append(missing_population)

        incoherent_unseeded = copy.deepcopy(state)
        incoherent_unseeded["objective"] = None
        malformed_states.append(incoherent_unseeded)

        for malformed in malformed_states:
            with self.subTest(malformed=malformed):
                with self.assertRaises((TypeError, ValueError)):
                    EvolutionaryPromptOptimizer.from_dict(malformed)


if __name__ == "__main__":
    unittest.main()
