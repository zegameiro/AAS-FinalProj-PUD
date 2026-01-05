"""
Visualization script for phishing detection model results.
Generates comprehensive plots for analysis and reporting.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.metrics import (
    confusion_matrix, 
    roc_curve, 
    auc, 
    precision_recall_curve,
    classification_report
)
from src.ai_models.knn_detector import KNNDetector
from src.ai_models.random_forest_detector import RandomForestDetector
from src.services.dataset_loader import fulldataset
import json
from pathlib import Path

# Set style for better-looking plots
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10

class PhishingVisualization:
    """Generate visualizations for phishing detection models"""
    
    def __init__(self, output_dir='visualizations'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = {}
        
    def generate_all_visualizations(self, models_dict, test_urls, test_labels):
        """Generate all visualization plots"""
        print("\n" + "="*60)
        print("GENERATING VISUALIZATIONS")
        print("="*60)
        
        # Get predictions for all models
        for model_name, model in models_dict.items():
            print(f"\nEvaluating {model_name}...")
            self.results[model_name] = self._get_model_metrics(model, test_urls, test_labels)
        
        # Generate individual plots
        self.plot_confusion_matrices(models_dict, test_urls, test_labels)
        self.plot_roc_curves(models_dict, test_urls, test_labels)
        self.plot_precision_recall_curves(models_dict, test_urls, test_labels)
        self.plot_model_comparison()
        self.plot_feature_importance(models_dict)
        self.plot_dataset_statistics()
        self.plot_confidence_distribution(models_dict, test_urls, test_labels)
        
        # Save metrics to JSON
        self._save_metrics()
        
        print(f"\n✓ All visualizations saved to '{self.output_dir}/' directory")
        
    def _get_model_metrics(self, model, test_urls, test_labels):
        """Calculate comprehensive metrics for a model"""
        # Prepare features
        x_test, y_test = model.prepare_data(test_urls, test_labels)
        
        # Predictions
        y_pred = model.classifier.predict(x_test)
        y_proba = model.classifier.predict_proba(x_test)[:, 1]
        
        # Calculate metrics
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, 
            f1_score, roc_auc_score
        )
        
        return {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_proba),
            'y_true': y_test,
            'y_pred': y_pred,
            'y_proba': y_proba
        }
    
    def plot_confusion_matrices(self, models_dict, test_urls, test_labels):
        """Plot confusion matrices for all models"""
        n_models = len(models_dict)
        fig, axes = plt.subplots(1, n_models, figsize=(6*n_models, 5))
        
        if n_models == 1:
            axes = [axes]
        
        for idx, (model_name, model) in enumerate(models_dict.items()):
            x_test, y_test = model.prepare_data(test_urls, test_labels)
            y_pred = model.classifier.predict(x_test)
            
            cm = confusion_matrix(y_test, y_pred)
            
            # Calculate percentages
            cm_percent = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis] * 100
            
            # Create annotations with both counts and percentages
            annotations = np.array([[f'{count}\n({percent:.1f}%)' 
                                   for count, percent in zip(row_counts, row_percents)]
                                  for row_counts, row_percents in zip(cm, cm_percent)])
            
            sns.heatmap(cm, annot=annotations, fmt='', cmap='Blues', 
                       cbar=True, ax=axes[idx],
                       xticklabels=['Legitimate', 'Phishing'],
                       yticklabels=['Legitimate', 'Phishing'])
            
            axes[idx].set_title(f'{model_name}\nConfusion Matrix', fontsize=14, fontweight='bold')
            axes[idx].set_ylabel('True Label', fontsize=12)
            axes[idx].set_xlabel('Predicted Label', fontsize=12)
            
            # Add metrics below the confusion matrix
            acc = self.results[model_name]['accuracy']
            f1 = self.results[model_name]['f1_score']
            axes[idx].text(0.5, -0.15, f'Accuracy: {acc:.4f} | F1-Score: {f1:.4f}', 
                          transform=axes[idx].transAxes, ha='center', fontsize=10)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'confusion_matrices.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved confusion matrices")
        plt.close()
    
    def plot_roc_curves(self, models_dict, test_urls, test_labels):
        """Plot ROC curves for all models"""
        plt.figure(figsize=(10, 8))
        
        colors = ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D', '#6A994E']
        
        for idx, (model_name, model) in enumerate(models_dict.items()):
            x_test, y_test = model.prepare_data(test_urls, test_labels)
            y_proba = model.classifier.predict_proba(x_test)[:, 1]
            
            fpr, tpr, _ = roc_curve(y_test, y_proba)
            roc_auc = auc(fpr, tpr)
            
            plt.plot(fpr, tpr, color=colors[idx % len(colors)], lw=2.5,
                    label=f'{model_name} (AUC = {roc_auc:.4f})')
        
        plt.plot([0, 1], [0, 1], 'k--', lw=2, label='Random Classifier (AUC = 0.5000)')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate', fontsize=12, fontweight='bold')
        plt.ylabel('True Positive Rate', fontsize=12, fontweight='bold')
        plt.title('ROC Curves - Model Comparison', fontsize=14, fontweight='bold')
        plt.legend(loc="lower right", fontsize=11)
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'roc_curves.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved ROC curves")
        plt.close()
    
    def plot_precision_recall_curves(self, models_dict, test_urls, test_labels):
        """Plot Precision-Recall curves"""
        plt.figure(figsize=(10, 8))
        
        colors = ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D', '#6A994E']
        
        for idx, (model_name, model) in enumerate(models_dict.items()):
            x_test, y_test = model.prepare_data(test_urls, test_labels)
            y_proba = model.classifier.predict_proba(x_test)[:, 1]
            
            precision, recall, _ = precision_recall_curve(y_test, y_proba)
            pr_auc = auc(recall, precision)
            
            plt.plot(recall, precision, color=colors[idx % len(colors)], lw=2.5,
                    label=f'{model_name} (AUC = {pr_auc:.4f})')
        
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('Recall', fontsize=12, fontweight='bold')
        plt.ylabel('Precision', fontsize=12, fontweight='bold')
        plt.title('Precision-Recall Curves - Model Comparison', fontsize=14, fontweight='bold')
        plt.legend(loc="lower left", fontsize=11)
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'precision_recall_curves.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved Precision-Recall curves")
        plt.close()
    
    def plot_model_comparison(self):
        """Bar chart comparing all metrics across models"""
        metrics = ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc']
        metric_labels = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC']
        
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        axes = axes.flatten()
        
        colors = ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D', '#6A994E']
        
        # Individual metric plots
        for idx, (metric, label) in enumerate(zip(metrics, metric_labels)):
            values = [self.results[model][metric] for model in self.results.keys()]
            model_names = list(self.results.keys())
            
            bars = axes[idx].bar(model_names, values, color=colors[:len(model_names)], alpha=0.8, edgecolor='black')
            axes[idx].set_ylabel(label, fontsize=11, fontweight='bold')
            axes[idx].set_title(f'{label} Comparison', fontsize=12, fontweight='bold')
            axes[idx].set_ylim([0, 1.1])
            axes[idx].grid(axis='y', alpha=0.3)
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                axes[idx].text(bar.get_x() + bar.get_width()/2., height,
                             f'{height:.4f}',
                             ha='center', va='bottom', fontweight='bold')
            
            # Rotate x-labels if needed
            axes[idx].tick_params(axis='x', rotation=45)
        
        # Grouped bar chart in the last subplot
        x = np.arange(len(list(self.results.keys())))
        width = 0.15
        
        for idx, (metric, label) in enumerate(zip(metrics, metric_labels)):
            values = [self.results[model][metric] for model in self.results.keys()]
            offset = width * (idx - len(metrics)/2)
            axes[5].bar(x + offset, values, width, label=label, alpha=0.8)
        
        axes[5].set_ylabel('Score', fontsize=11, fontweight='bold')
        axes[5].set_title('All Metrics Comparison', fontsize=12, fontweight='bold')
        axes[5].set_xticks(x)
        axes[5].set_xticklabels(list(self.results.keys()))
        axes[5].legend(loc='lower right', fontsize=9)
        axes[5].set_ylim([0, 1.1])
        axes[5].grid(axis='y', alpha=0.3)
        axes[5].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'model_comparison.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved model comparison")
        plt.close()
    
    def plot_feature_importance(self, models_dict):
        """Plot feature importance for models that support it"""
        for model_name, model in models_dict.items():
            if hasattr(model.classifier, 'feature_importances_'):
                importances = model.classifier.feature_importances_
                indices = np.argsort(importances)[::-1][:20]  # Top 20
                
                plt.figure(figsize=(12, 8))
                
                feature_names = [model.feature_names[i] for i in indices]
                feature_values = [importances[i] for i in indices]
                
                # Create horizontal bar chart
                y_pos = np.arange(len(feature_names))
                bars = plt.barh(y_pos, feature_values, color='#2E86AB', alpha=0.8, edgecolor='black')
                
                plt.yticks(y_pos, feature_names)
                plt.xlabel('Importance Score', fontsize=12, fontweight='bold')
                plt.title(f'{model_name} - Top 20 Feature Importance', fontsize=14, fontweight='bold')
                plt.gca().invert_yaxis()
                
                # Add value labels
                for i, (bar, value) in enumerate(zip(bars, feature_values)):
                    plt.text(value, bar.get_y() + bar.get_height()/2, 
                           f'{value:.4f}', 
                           ha='left', va='center', fontweight='bold', fontsize=9)
                
                plt.tight_layout()
                filename = f"feature_importance_{model_name.lower().replace(' ', '_')}.png"
                plt.savefig(self.output_dir / filename, dpi=300, bbox_inches='tight')
                print(f"✓ Saved feature importance for {model_name}")
                plt.close()
    
    def plot_dataset_statistics(self):
        """Plot dataset distribution and statistics"""
        urls, labels = fulldataset.get_urls_and_labels()
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # 1. Class distribution pie chart
        phishing_count = sum(labels)
        benign_count = len(labels) - phishing_count
        
        colors_pie = ['#6A994E', '#BC4749']
        explode = (0.05, 0.05)
        
        axes[0, 0].pie([benign_count, phishing_count], 
                      labels=['Legitimate', 'Phishing'],
                      autopct='%1.1f%%',
                      colors=colors_pie,
                      explode=explode,
                      startangle=90,
                      textprops={'fontsize': 12, 'fontweight': 'bold'})
        axes[0, 0].set_title('Dataset Class Distribution', fontsize=14, fontweight='bold')
        
        # 2. Class counts bar chart
        categories = ['Legitimate', 'Phishing']
        counts = [benign_count, phishing_count]
        
        bars = axes[0, 1].bar(categories, counts, color=colors_pie, alpha=0.8, edgecolor='black')
        axes[0, 1].set_ylabel('Count', fontsize=12, fontweight='bold')
        axes[0, 1].set_title('Sample Counts by Class', fontsize=14, fontweight='bold')
        axes[0, 1].grid(axis='y', alpha=0.3)
        
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            axes[0, 1].text(bar.get_x() + bar.get_width()/2., height,
                          f'{int(count):,}',
                          ha='center', va='bottom', fontweight='bold', fontsize=11)
        
        # 3. URL length distribution
        url_lengths = [len(url) for url in urls]
        phishing_lengths = [len(urls[i]) for i in range(len(urls)) if labels[i] == 1]
        benign_lengths = [len(urls[i]) for i in range(len(urls)) if labels[i] == 0]
        
        axes[1, 0].hist([benign_lengths, phishing_lengths], bins=50, 
                       label=['Legitimate', 'Phishing'],
                       color=['#6A994E', '#BC4749'], alpha=0.7, edgecolor='black')
        axes[1, 0].set_xlabel('URL Length (characters)', fontsize=11, fontweight='bold')
        axes[1, 0].set_ylabel('Frequency', fontsize=11, fontweight='bold')
        axes[1, 0].set_title('URL Length Distribution by Class', fontsize=14, fontweight='bold')
        axes[1, 0].legend()
        axes[1, 0].grid(axis='y', alpha=0.3)
        
        # 4. Statistics table
        stats_data = [
            ['Total URLs', f'{len(urls):,}'],
            ['Legitimate URLs', f'{benign_count:,}'],
            ['Phishing URLs', f'{phishing_count:,}'],
            ['Phishing Ratio', f'{phishing_count/len(labels)*100:.2f}%'],
            ['Avg URL Length (Legitimate)', f'{np.mean(benign_lengths):.1f}'],
            ['Avg URL Length (Phishing)', f'{np.mean(phishing_lengths):.1f}'],
        ]
        
        axes[1, 1].axis('tight')
        axes[1, 1].axis('off')
        table = axes[1, 1].table(cellText=stats_data, 
                                colLabels=['Metric', 'Value'],
                                cellLoc='left',
                                loc='center',
                                colWidths=[0.6, 0.4])
        table.auto_set_font_size(False)
        table.set_fontsize(11)
        table.scale(1, 2.5)
        
        # Style the table
        for i in range(len(stats_data) + 1):
            if i == 0:  # Header
                table[(i, 0)].set_facecolor('#2E86AB')
                table[(i, 1)].set_facecolor('#2E86AB')
                table[(i, 0)].set_text_props(weight='bold', color='white')
                table[(i, 1)].set_text_props(weight='bold', color='white')
            else:
                table[(i, 0)].set_facecolor('#E8E8E8' if i % 2 == 0 else 'white')
                table[(i, 1)].set_facecolor('#E8E8E8' if i % 2 == 0 else 'white')
        
        axes[1, 1].set_title('Dataset Statistics Summary', fontsize=14, fontweight='bold', pad=20)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'dataset_statistics.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved dataset statistics")
        plt.close()
    
    def plot_confidence_distribution(self, models_dict, test_urls, test_labels):
        """Plot prediction confidence distribution"""
        n_models = len(models_dict)
        fig, axes = plt.subplots(1, n_models, figsize=(7*n_models, 5))
        
        if n_models == 1:
            axes = [axes]
        
        for idx, (model_name, model) in enumerate(models_dict.items()):
            x_test, y_test = model.prepare_data(test_urls, test_labels)
            y_proba = model.classifier.predict_proba(x_test)
            
            # Get confidence for predicted class
            confidence = np.max(y_proba, axis=1)
            
            # Separate by correct/incorrect predictions
            y_pred = model.classifier.predict(x_test)
            correct_conf = confidence[y_pred == y_test]
            incorrect_conf = confidence[y_pred != y_test]
            
            axes[idx].hist([correct_conf, incorrect_conf], bins=30, 
                          label=['Correct Predictions', 'Incorrect Predictions'],
                          color=['#6A994E', '#BC4749'], alpha=0.7, edgecolor='black')
            
            axes[idx].set_xlabel('Confidence Score', fontsize=11, fontweight='bold')
            axes[idx].set_ylabel('Frequency', fontsize=11, fontweight='bold')
            axes[idx].set_title(f'{model_name}\nPrediction Confidence Distribution', 
                               fontsize=12, fontweight='bold')
            axes[idx].legend()
            axes[idx].grid(axis='y', alpha=0.3)
            
            # Add statistics
            avg_correct = np.mean(correct_conf)
            avg_incorrect = np.mean(incorrect_conf)
            axes[idx].axvline(avg_correct, color='#6A994E', linestyle='--', linewidth=2, 
                            label=f'Avg Correct: {avg_correct:.3f}')
            axes[idx].axvline(avg_incorrect, color='#BC4749', linestyle='--', linewidth=2,
                            label=f'Avg Incorrect: {avg_incorrect:.3f}')
            axes[idx].legend()
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'confidence_distribution.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved confidence distribution")
        plt.close()
    
    def _save_metrics(self):
        """Save all metrics to JSON file"""
        metrics_export = {}
        for model_name, metrics in self.results.items():
            metrics_export[model_name] = {
                'accuracy': float(metrics['accuracy']),
                'precision': float(metrics['precision']),
                'recall': float(metrics['recall']),
                'f1_score': float(metrics['f1_score']),
                'roc_auc': float(metrics['roc_auc'])
            }
        
        with open(self.output_dir / 'metrics.json', 'w') as f:
            json.dump(metrics_export, f, indent=4)
        
        print(f"✓ Saved metrics to JSON")


def main():
    """Main function to generate all visualizations"""
    print("\n" + "="*60)
    print("PHISHING DETECTION - VISUALIZATION GENERATOR")
    print("="*60)
    
    # Load dataset
    print("\nLoading dataset...")
    urls, labels = fulldataset.get_urls_and_labels()
    
    # Split data
    train_urls, train_labels, test_urls, test_labels = fulldataset.split_train_test_datasets(
        test_size=0.15,
        balance_test=True,
        random_seed=42
    )
    
    print(f"Training samples: {len(train_urls)}")
    print(f"Test samples: {len(test_urls)}")
    
    # Initialize models
    models = {}
    
    print("\n" + "="*60)
    print("Choose which models to visualize:")
    print("1. Random Forest only")
    print("2. KNN only")
    print("3. Both models")
    print("="*60)
    
    choice = input("Enter choice (1/2/3) [default: 3]: ").strip() or "3"
    
    if choice in ['1', '3']:
        print("\nLoading Random Forest model...")
        try:
            rf_detector = RandomForestDetector.load_model('models/phishing_detector_rf.pkl')
            models['Random Forest'] = rf_detector
            print("✓ Random Forest loaded from saved model")
        except:
            print("Training new Random Forest model...")
            rf_detector = RandomForestDetector(n_estimators=200)
            rf_detector.train(train_urls, train_labels, test_size=0.2)
            rf_detector.save_model('models/phishing_detector_rf.pkl')
            models['Random Forest'] = rf_detector
    
    if choice in ['2', '3']:
        print("\nLoading KNN model...")
        try:
            knn_detector = KNNDetector.load_model('models/phishing_detector_knn.pkl')
            models['KNN'] = knn_detector
            print("✓ KNN loaded from saved model")
        except:
            print("Training new KNN model...")
            knn_detector = KNNDetector(n_neighbors=7, weights='distance')
            knn_detector.train(train_urls, train_labels, test_size=0.2)
            knn_detector.save_model('models/phishing_detector_knn.pkl')
            models['KNN'] = knn_detector
    
    # Generate visualizations
    viz = PhishingVisualization()
    viz.generate_all_visualizations(models, test_urls, test_labels)
    
    print("\n" + "="*60)
    print("VISUALIZATION GENERATION COMPLETE!")
    print("="*60)
    print(f"\nAll plots have been saved to the 'visualizations/' directory:")
    print("  - confusion_matrices.png")
    print("  - roc_curves.png")
    print("  - precision_recall_curves.png")
    print("  - model_comparison.png")
    print("  - feature_importance_*.png")
    print("  - dataset_statistics.png")
    print("  - confidence_distribution.png")
    print("  - metrics.json")
    print("\nYou can now use these visualizations in your report!")


if __name__ == "__main__":
    main()
